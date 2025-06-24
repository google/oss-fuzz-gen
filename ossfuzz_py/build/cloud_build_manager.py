# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""
Cloud Build Manager for managing cloud build operations.

This module provides the CloudBuildManager class that handles cloud build
operations such as submitting builds, monitoring status, and managing build
lifecycle."""

import logging
import os
import random
import re
import subprocess as sp
import time
import uuid
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

from google.cloud import storage

from ossfuzz_py.errors import CloudBuildError
# Import centralized environment utilities
from ossfuzz_py.utils.env_utils import EnvUtils
from ossfuzz_py.utils.env_vars import EnvVars

logger = logging.getLogger('ossfuzz_sdk.build.cloud_build_manager')


class BuildStatus(Enum):
  """Status of a cloud build operation."""
  IN_PROGRESS = "IN_PROGRESS"
  SUCCESS = "SUCCESS"
  FAILURE = "FAILURE"
  TIMEOUT = "TIMEOUT"
  CANCELLED = "CANCELLED"
  UNKNOWN = "UNKNOWN"


# Constants from the original implementation
CLOUD_EXP_MAX_ATTEMPT = 5
RUN_TIMEOUT = 30

# Regex patterns for libfuzzer log parsing
LIBFUZZER_MODULES_LOADED_REGEX = re.compile(
    r'^INFO:\s+Loaded\s+\d+\s+(modules|PC tables)\s+\((\d+)\s+.*\).*')
LIBFUZZER_COV_REGEX = re.compile(r'.*cov: (\d+) ft:')
LIBFUZZER_CRASH_TYPE_REGEX = re.compile(r'.*Test unit written to.*')
LIBFUZZER_COV_LINE_PREFIX = re.compile(r'^#(\d+)')
LIBFUZZER_STACK_FRAME_LINE_PREFIX = re.compile(r'^\s+#\d+')
CRASH_EXCLUSIONS = re.compile(r'.*(slow-unit-|timeout-|leak-|oom-).*')
CRASH_STACK_WITH_SOURCE_INFO = re.compile(r'in.*:\d+:\d+$')

LIBFUZZER_LOG_STACK_FRAME_LLVM = '/src/llvm-project/compiler-rt'
LIBFUZZER_LOG_STACK_FRAME_LLVM2 = '/work/llvm-stage2/projects/compiler-rt'
LIBFUZZER_LOG_STACK_FRAME_CPP = '/usr/local/bin/../include/c++'

EARLY_FUZZING_ROUND_THRESHOLD = 3


class CloudBuildManager:
  """
  Manages cloud build operations including submission, monitoring,
  and lifecycle management.

  This class provides a high-level interface for cloud build operations,
  abstracting the complexities of different cloud build services.
  Enhanced with robust retry logic and OSS-Fuzz integration.
  """

  def __init__(self,
               project_id: str,
               experiment_bucket: str,
               experiment_name: str,
               region: str = "us-west2",
               max_retries: int = CLOUD_EXP_MAX_ATTEMPT):
    """
    Initialize the CloudBuildManager.

    Args:
        project_id: Cloud project ID
        experiment_bucket: GCS bucket for experiment artifacts
        experiment_name: Name of the experiment
        region: Cloud region for builds
        max_retries: Maximum number of retries for failed operations
    """
    self.project_id = project_id
    self.experiment_bucket = experiment_bucket
    self.experiment_name = experiment_name
    self.region = region
    self.max_retries = max_retries
    self.logger = logger

    self._setup_environment()

    # Initialize Google Cloud Storage client
    self.storage_client = storage.Client()
    self.bucket = self.storage_client.bucket(self.experiment_bucket)

    # Track active builds
    self._active_builds: Dict[str, Dict[str, Any]] = {}

    # Retryable errors with exponential backoff functions
    self.retryable_errors = [
        ('RESOURCE_EXHAUSTED', lambda x: 5 * 2**x + random.randint(50, 90)),
        ('BrokenPipeError: [Errno 32] Broken pipe',
         lambda x: 5 * 2**x + random.randint(1, 5)),
        ('Service Unavailable', lambda x: 5 * 2**x + random.randint(1, 5)),
        ('You do not currently have an active account selected',
         lambda x: 5 * 2**x),
        ('gcloud crashed (OSError): unexpected end of data',
         lambda x: 5 * 2**x),
    ]

    self.logger.debug(
        "Initialized CloudBuildManager for project %s in region %s", project_id,
        region)

  def _setup_environment(self) -> bool:
    """Set up the cloud build environment."""
    try:
      self.logger.info("Setting up cloud build environment")
      # Cloud environment setup would involve checking credentials,
      # permissions, etc.
      google_creds = EnvUtils.get_env(EnvVars.GOOGLE_APPLICATION_CREDENTIALS)
      if google_creds:
        logging.info("GOOGLE APPLICATION CREDENTIALS set: %s.", google_creds)
        self._run_command([
            'gcloud', 'auth', 'activate-service-account',
            '803802421675-compute@developer.gserviceaccount.com', '--key-file',
            google_creds
        ])
      else:
        logging.info("GOOGLE APPLICATION CREDENTIALS is not set.")
      return True
    except Exception as e:
      self.logger.error("Failed to setup cloud environment: %s", e)
      return False

  def _run_command(self, command: list[str], shell=False):
    """Runs a command and return its exit code."""
    process = sp.run(command, shell=shell, check=False)
    return process.returncode

  def _libfuzzer_args(self, run_timeout: int = RUN_TIMEOUT) -> list[str]:
    return [
        '-print_final_stats=1',
        f'-max_total_time={run_timeout}',
        # Without this flag, libFuzzer only consider short inputs in short
        # experiments, which lowers the coverage for quick performance tests.
        '-len_control=0',
        # Timeout per testcase.
        '-timeout=30',
        '-detect_leaks=0',
    ]

  def build_cloud_build_command(
      self,
      generated_project: str,
      benchmark_target_name: str,
      project_name: str,
      cloud_build_tags: Optional[List[str]] = None) -> List[str]:
    """Build the command for cloud build execution (build-only)."""
    # Determine OSS-Fuzz checkout directory
    venv_dir = EnvUtils.get_venv_dir()

    uid = self.experiment_name + str(uuid.uuid4())
    run_log_name = f'{uid}.run.log'
    run_log_path = f'gs://{self.experiment_bucket}/{run_log_name}'

    build_log_name = f'{uid}.build.log'
    build_log_path = f'gs://{self.experiment_bucket}/{build_log_name}'

    corpus_name = f'{uid}.corpus.zip'
    corpus_path = f'gs://{self.experiment_bucket}/{corpus_name}'

    coverage_name = f'{uid}.coverage'
    coverage_path = f'gs://{self.experiment_bucket}/{coverage_name}'

    reproducer_name = f'{uid}.reproducer'
    reproducer_path = f'gs://{self.experiment_bucket}/{reproducer_name}'

    self.logger.info('Service account key: %s',
                     EnvUtils.get_env(EnvVars.GOOGLE_APPLICATION_CREDENTIALS))
    command = [
        f'{venv_dir}/bin/python3',
        'infra/build/functions/target_experiment.py',
        f'--project={generated_project}',
        f'--target={benchmark_target_name}',
        f'--upload_build_log={build_log_path}',
        f'--upload_output_log={run_log_path}',
        f'--upload_coverage={coverage_path}',
        f'--upload_reproducer={reproducer_path}',
        f'--upload_corpus={corpus_path}',
        f'--experiment_name={self.experiment_name}',
        f'--real_project={project_name}',
        f'--cloud_project={self.experiment_bucket}',
    ]

    if cloud_build_tags:
      command += ['--tags'] + cloud_build_tags
    command += ['--'] + self._libfuzzer_args()

    return command

  # NOTE: Running logic has been moved to CloudRunner
  # (see ossfuzz_py/execution/cloud_runner.py)
  # The CloudRunner will handle:
  # - target_experiment.py execution with running parameters
  # - _parse_libfuzzer_logs()
  # - Coverage and crash analysis
  # - Result processing and artifact download
  # - Corpus, coverage, and reproducer management

  def run_with_retry_control(self, target_path: str,
                             command: List[str]) -> bool:
    """Execute command with controllable retry and customized exponential
    backoff."""
    oss_fuzz_dir = EnvUtils.get_oss_fuzz_dir()

    for attempt_id in range(1, self.max_retries + 1):
      try:
        sp.run(command,
               check=True,
               cwd=oss_fuzz_dir,
               capture_output=True,
               text=True)
        return True
      except sp.CalledProcessError as e:
        # Replace \n for single log entry on cloud
        stdout = e.stdout.replace('\n', '\t') if e.stdout else ''
        stderr = e.stderr.replace('\n', '\t') if e.stderr else ''

        delay = next((delay_f(attempt_id)
                      for err, delay_f in self.retryable_errors
                      if err in stdout + stderr), 0)

        if not delay or attempt_id == self.max_retries:
          self.logger.error(
              'Failed to evaluate %s on cloud, attempt %d:\n%s\n%s',
              os.path.realpath(target_path), attempt_id, stdout, stderr)
          break

        self.logger.warning(
            'Failed to evaluate %s on cloud, attempt %d, retry in %ds:\n'
            '%s\n%s', os.path.realpath(target_path), attempt_id, delay, stdout,
            stderr)
        time.sleep(delay)

    self.logger.info('Cloud build execution completed for %s.',
                     os.path.realpath(target_path))
    return False

  # NOTE: The following methods have been moved to CloudRunner:
  # - _process_cloud_build_results()
  # - _process_coverage_reports()
  # - _parse_libfuzzer_logs()
  # - _parse_fuzz_cov_info_from_libfuzzer_logs()
  # - _extract_crash_info()
  # - _perform_semantic_check()
  # - _get_cloud_textcov_path()
  # These methods handle running results, not build results

  def get_build_status(self, build_id: str) -> BuildStatus:
    """
    Get the current status of a build.

    Args:
        build_id: Build ID to check

    Returns:
        BuildStatus: Current status of the build
    """
    try:
      if build_id not in self._active_builds:
        self.logger.warning("Build %s not found in active builds", build_id)
        return BuildStatus.UNKNOWN

      # TODO: Implement actual status checking with cloud provider
      # This is a simulation for now
      build_info = self._active_builds[build_id]
      elapsed_time = time.time() - build_info['start_time']

      # Simulate build completion after some time
      if elapsed_time > 30:  # 30 seconds for simulation
        # Randomly succeed or fail for simulation
        if random.random() > 0.2:  # 80% success rate
          build_info['status'] = BuildStatus.SUCCESS
        else:
          build_info['status'] = BuildStatus.FAILURE

      status = build_info['status']
      self.logger.debug("Build %s status: %s", build_id, status)
      return status

    except Exception as e:
      self.logger.error("Failed to get build status for %s: %s", build_id, e)
      return BuildStatus.UNKNOWN

  def wait_for_build(self, build_id: str, timeout: int = 3600) -> BuildStatus:
    """
    Wait for a build to complete.

    Args:
        build_id: Build ID to wait for
        timeout: Maximum time to wait in seconds

    Returns:
        BuildStatus: Final status of the build
    """
    start_time = time.time()
    poll_interval = 10  # Poll every 10 seconds

    self.logger.info("Waiting for build %s to complete (timeout: %ss)",
                     build_id, timeout)

    while time.time() - start_time < timeout:
      status = self.get_build_status(build_id)

      if status in [
          BuildStatus.SUCCESS, BuildStatus.FAILURE, BuildStatus.CANCELLED
      ]:
        self.logger.info("Build %s completed with status: %s", build_id, status)
        return status

      time.sleep(poll_interval)

    # Timeout reached
    self.logger.warning("Build %s timed out after %s seconds", build_id,
                        timeout)
    if build_id in self._active_builds:
      self._active_builds[build_id]['status'] = BuildStatus.TIMEOUT

    return BuildStatus.TIMEOUT

  def submit_build(self, build_config: Dict[str, Any], source: Path) -> str:
    """
    Submit a build to the cloud build service.

    Args:
        build_config: Build configuration dictionary
        source: Path to source code directory

    Returns:
        str: Build ID for tracking the build

    Raises:
        CloudBuildError: If build submission fails
    """
    try:
      # Generate a unique build ID
      build_id = f"build-{uuid.uuid4().hex[:8]}"

      self.logger.info("Submitting cloud build %s for source: %s", build_id,
                       source)

      # Store build information
      self._active_builds[build_id] = {
          'config': build_config,
          'source': str(source),
          'status': BuildStatus.IN_PROGRESS,
          'start_time': time.time(),
          'retries': 0
      }

      self.logger.info("Cloud build %s submitted successfully", build_id)
      return build_id

    except Exception as e:
      self.logger.error("Failed to submit cloud build: %s", e)
      raise CloudBuildError(f"Failed to submit cloud build: {e}")
