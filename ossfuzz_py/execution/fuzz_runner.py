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
Abstract FuzzRunner interface for the Custom Fuzzing Module.

This module defines the abstract FuzzRunner interface and its implementations
for executing fuzz tests in various environments (local, cloud).
It provides a clean abstraction over the complexities of fuzzing engines
while maintaining loose coupling with the underlying implementations.

The architecture follows the design described in the task:
- FuzzRunner (abstract): Defines the interface for all runner implementations
- LocalRunner: Concrete implementation for local fuzzing environments
- CloudRunner: Concrete implementation for cloud-based fuzzing
- Supporting classes for monitoring, result collection, and run configuration

For usage examples, see the jupyter notebooks in the examples directory.
"""
import logging
import random
import re
import subprocess
import time
import uuid
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Dict, List, Optional

from google.cloud import storage
from pydantic import BaseModel, Field

# Import ResultManager for result storage
from ossfuzz_py.core.benchmark_manager import Benchmark
from ossfuzz_py.core.data_models import FuzzingEngine, Sanitizer
from ossfuzz_py.result.results import Result, RunInfo
from ossfuzz_py.utils.env_utils import EnvUtils
from ossfuzz_py.utils.work_dir_manager import WorkDirManager

# Configure module logger
logger = logging.getLogger('ossfuzz_sdk.fuzz_runner')


class FuzzRunOptions(BaseModel):
  """Options for a fuzzing run."""
  engine: FuzzingEngine = FuzzingEngine.LIBFUZZER
  sanitizers: List[Sanitizer] = Field(
      default_factory=lambda: [Sanitizer.ADDRESS])
  duration_seconds: Optional[
      int] = 3600  # Max time in seconds for the entire run
  timeout_seconds: Optional[int] = 25  # Max time for a single input
  max_memory_mb: Optional[int] = 1024  # Max memory for the fuzzer (in MB)
  max_total_time: Optional[
      int] = None  # Alias for duration_seconds (backward compatibility)
  max_individual_test_time: Optional[
      int] = None  # Alias for timeout_seconds (backward compatibility)
  detect_leaks: bool = True  # Whether to detect memory leaks
  extract_coverage: bool = False
  corpus_dir: Optional[str] = None
  output_dir: Optional[
      str] = "fuzz_output"  # Relative to a run-specific directory
  engine_args: List[str] = Field(default_factory=list)
  env_vars: Dict[str, str] = Field(default_factory=dict)


class FuzzRunner(ABC):
  """
  Abstract Base Class for Fuzz Runners.
  Defines a common interface for executing fuzz targets
  in different environments
  (e.g., local Docker, cloud instances).
  """

  def __init__(self):
    self.logger = logger

  @abstractmethod
  def run(self, target: str, options: FuzzRunOptions,
          build_metadata: Dict[str, Any]) -> RunInfo:
    """
    Run a fuzz target using build metadata.
    """

  def parse_libfuzzer_logs(self, log_handle,
                           project_name: str) -> Dict[str, Any]:
    """Parse libfuzzer logs to extract coverage and crash information."""
    # Constants for parsing (migrated from the old implementation)
    libfuzzer_modules_loaded_regex = re.compile(
        r'^INFO:\s+Loaded\s+\d+\s+(modules|PC tables)\s+\((\d+)\s+.*\).*')
    libfuzzer_cov_regex = re.compile(r'.*cov: (\d+) ft:')
    libfuzzer_crash_type_regex = re.compile(r'.*Test unit written to.*')
    crash_exclusions = re.compile(r'.*(slow-unit-|timeout-|leak-|oom-).*')

    try:
      fuzzlog = log_handle.read(-1)
      fuzzlog = fuzzlog.decode('utf-8', errors='ignore')
      lines = fuzzlog.split('\n')
    except MemoryError as e:
      self.logger.error('%s is too large to parse: %s, project: %s',
                        log_handle.name, e, project_name)
      return {'cov_pcs': 0, 'total_pcs': 0, 'crashes': False, 'crash_info': ''}

    cov_pcs, total_pcs, crashes = 0, 0, False
    crash_info = ''

    for line in lines:
      m = libfuzzer_modules_loaded_regex.match(line)
      if m:
        total_pcs = int(m.group(2))
        continue

      m = libfuzzer_cov_regex.match(line)
      if m:
        cov_pcs = int(m.group(1))
        continue

      m = libfuzzer_crash_type_regex.match(line)
      if m and not crash_exclusions.match(line):
        crashes = True
        crash_info = line
        continue

    return {
        'cov_pcs': cov_pcs,
        'total_pcs': total_pcs,
        'crashes': crashes,
        'crash_info': crash_info
    }


class LocalRunner(FuzzRunner):
  """
  Concrete implementation of FuzzRunner for local execution.

  This runner executes fuzzing targets on the local machine using
  Docker containers and consumes metadata from LocalBuilder.
  Implements the standardized Runner interface as per UML design.
  """

  def __init__(self,
               work_dir_manager: WorkDirManager,
               result_manager: Any = None):
    """Initialize LocalRunner with Docker manager integration."""
    super().__init__()
    self.work_dir_manager = work_dir_manager
    self.result_manager = result_manager

  def run(self,
          target: str,
          options: FuzzRunOptions,
          build_metadata: Dict[str, Any],
          benchmark_id: Optional[str] = None,
          trial: int = 1) -> RunInfo:
    """
    Run a fuzz target using build metadata from LocalBuilder.

    Args:
        target: Target name to run
        options: Fuzzing options
        build_metadata: Metadata from LocalBuilder containing build artifacts
        benchmark_id: Optional benchmark ID for result storage
        trial: Trial number for result storage

    Returns:
        RunInfo: Standardized result data structure
    """
    # Create RunInfo instance
    run_info = RunInfo()

    try:
      # Execute the fuzzer using build metadata
      success = self._run_target_local(build_metadata, target, options,
                                       run_info)
      self.logger.info("Local run successful: %s", success)

    except Exception as e:
      self.logger.error("Local run failed: %s", e)
      run_info.error_message = str(e)

    # Store result through ResultManager if available
    self._store_run_result(target, run_info, build_metadata, benchmark_id,
                           trial)

    return run_info

  # Core Local Running Logic (migrated from old implementation)
  def _run_target_local(self, build_metadata: Dict[str, Any], target_name: str,
                        options: FuzzRunOptions, run_info: RunInfo) -> bool:
    """
    Run a fuzz target locally using build metadata from LocalBuilder.

    Args:
        build_metadata: Build metadata from LocalBuilder
        target_name: Name of the target to run
        options: Fuzzing options
        run_info: RunInfo instance to update with results

    Returns:
        bool: True if run was successful
    """
    self.logger.info('Running %s locally', target_name)

    # Extract information from build metadata
    generated_project = build_metadata.get('generated_project')
    if not generated_project or not isinstance(generated_project, str):
      raise ValueError(
          "Generated project name is required and must be a string")
    oss_fuzz_dir = EnvUtils.get_oss_fuzz_dir()

    self.work_dir_manager.create_run_dir(generated_project, target_name)

    log_path = str(
        self.work_dir_manager.get_run_logs_dir(generated_project, target_name) /
        f'{target_name}.log')
    corpus_dir = str(
        self.work_dir_manager.get_run_corpus_dir(generated_project,
                                                 target_name))

    # Update run_info with paths
    run_info.run_log = log_path
    run_info.corpus_path = corpus_dir

    # Prepare libfuzzer arguments
    libfuzzer_args = self._get_libfuzzer_args(options)
    venv_dir = EnvUtils.get_venv_dir()

    # Run using OSS-Fuzz helper.py
    command = [
        f'{venv_dir}/bin/python3', 'infra/helper.py', 'run_fuzzer',
        '--corpus-dir', corpus_dir, generated_project, target_name, '--'
    ] + libfuzzer_args

    try:
      with open(log_path, 'w') as log_file:
        result = subprocess.run(
            command,
            cwd=oss_fuzz_dir,
            stdout=log_file,
            stderr=subprocess.STDOUT,
            timeout=(options.duration_seconds or 3600) + 10,
            text=True,
            check=True,
        )

      self.logger.info('Fuzzer run completed with return code: %d',
                       result.returncode)

      # Parse libfuzzer logs for coverage and crash information
      self._parse_and_update_run_results(log_path, run_info,
                                         build_metadata.get('project_name', ''))

      # Extract coverage if requested
      # if options.extract_coverage:
      #   self._extract_coverage_local(build_metadata, target_name, run_info)

      return True

    except subprocess.TimeoutExpired:
      self.logger.warning('Fuzzer run timed out')
      run_info.timeout = True
      return True  # Timeout is expected for fuzzers
    except Exception as e:
      self.logger.error('Failed to run fuzzer: %s', e)
      run_info.error_message = str(e)
      return False

  def _get_libfuzzer_args(self, options: FuzzRunOptions) -> List[str]:
    """Get libfuzzer arguments from run options."""
    args = [
        '-print_final_stats=1',
        f'-max_total_time={options.duration_seconds or 3600}',
        '-len_control=0',
        f'-timeout={options.timeout_seconds or 25}',
    ]

    if not options.detect_leaks:
      args.append('-detect_leaks=0')

    return args

  def _store_run_result(self, target: str, run_info: RunInfo,
                        build_metadata: Dict[str, Any],
                        benchmark_id: Optional[str], trial: int) -> None:
    """Store run result through ResultManager if available."""
    if not self.result_manager:
      return

    try:
      # Create minimal benchmark for the result
      if Benchmark is None:
        self.logger.warning("Benchmark class not available")
        return

      benchmark = Benchmark(
          project=build_metadata.get('project_name', 'unknown'),
          language='c++',  # Default language
          function_signature=f'int {target}(const uint8_t* data, size_t size)',
          function_name=target,
          return_type='int',
          target_path='',
          id=benchmark_id or target,
      )

      # Create Result object for storage
      if Result is None:
        self.logger.warning("Result class not available")
        return

      result_obj = Result(
          benchmark=benchmark,
          work_dirs='',
          trial=trial,
          run_info=run_info,
      )

      # Store through ResultManager
      self.result_manager.store_result(benchmark_id or target, result_obj)
      self.logger.debug("Stored run result for %s through ResultManager",
                        benchmark_id or target)

    except Exception as e:
      self.logger.warning(
          "Failed to store run result through ResultManager: %s", e)

  def _parse_and_update_run_results(self, log_path: str, run_info: 'RunInfo',
                                    project_name: str):
    """Parse libfuzzer logs and update run_info with results."""
    try:
      with open(log_path, 'rb') as f:
        parse_result = self.parse_libfuzzer_logs(f, project_name)

      # Update run_info with parsed results
      run_info.cov_pcs = parse_result.get('cov_pcs', 0)
      run_info.total_pcs = parse_result.get('total_pcs', 0)
      run_info.crashes = parse_result.get('crashes', False)
      run_info.crash_info = parse_result.get('crash_info', '')

      if run_info.crashes:
        reproducer_path = self._find_reproducer_files(log_path)
        run_info.reproducer_path = reproducer_path or ''

    except Exception as e:
      self.logger.error('Failed to parse libfuzzer logs: %s', e)

  def _find_reproducer_files(self, log_path: str) -> Optional[str]:
    """Find reproducer files mentioned in the log."""
    try:
      with open(log_path, 'r') as f:
        content = f.read()

      # Look for "Test unit written to" pattern
      pattern = r'Test unit written to (.+)'
      matches = re.findall(pattern, content)
      if matches:
        return matches[0].strip()
    except Exception as e:
      self.logger.error('Failed to find reproducer files: %s', e)
    return None

  # def _extract_coverage_local(self, build_metadata: Dict[str, Any],
  #                             target_name: str, run_info: 'RunInfo'):
  #   """Extract coverage information for the target."""
  #   # TODO: Implement coverage extraction using OSS-Fuzz coverage tools
  #   # This would involve:
  #   # 1. Building with coverage sanitizer
  #   # 2. Running coverage extraction
  #   # 3. Processing textcov reports
  #   # 4. Updating run_info with coverage data
  #   self.logger.info('Coverage extraction not yet implemented for %s',
  #                    target_name)


class CloudRunner(FuzzRunner):
  """
  Concrete implementation of FuzzRunner for cloud execution.

  This runner executes fuzzing targets in cloud environments
  such as Google Cloud Platform or AWS.
  """

  def __init__(self):
    """Initialize CloudRunner with cloud integration."""
    super().__init__()
    self.cloud_config = {}

    # Cloud-specific configuration
    self.experiment_name = self.cloud_config.get('experiment_name',
                                                 'default-experiment')
    self.experiment_bucket = self.cloud_config.get('experiment_bucket',
                                                   'default-bucket')

    # Import cloud dependencies
    try:
      self.storage_client = storage.Client()
    except Exception as e:
      self.logger.warning(
          "Failed to initialize Google Cloud Storage client: %s", e)
      self.storage_client = None

  # Standardized Runner Interface Methods (as per UML design)

  def run(self, target: str, options: FuzzRunOptions,
          build_metadata: Dict[str, Any]) -> 'RunInfo':
    """
    Run a fuzz target using build metadata from CloudBuilder.

    Args:
        target: Target name to run
        options: Fuzzing options
        build_metadata: Metadata from CloudBuilder containing build artifacts

    Returns:
        RunInfo: Standardized result data structure
    """

    # Create RunInfo instance
    run_info = RunInfo()

    try:
      # Execute the fuzzer using build metadata
      success = self._run_target_cloud(build_metadata, target, options,
                                       run_info)
      self.logger.info("Cloud run successful: %s", success)

    except Exception as e:
      self.logger.error("Cloud run failed: %s", e)

    return run_info

  def get_logs(self, target: str) -> Optional[str]:
    """
    Get logs for a target from cloud storage.

    Args:
        target: Target name

    Returns:
        Optional[str]: Log content or None if not found
    """
    if not self.storage_client:
      return None

    try:
      bucket = self.storage_client.bucket(self.experiment_bucket)
      # Look for log files with target name pattern
      blobs = bucket.list_blobs(prefix=f"{target}_")
      for blob in blobs:
        if blob.name.endswith('.run.log'):
          return blob.download_as_text()
    except Exception as e:
      self.logger.error("Failed to get logs for %s: %s", target, e)
    return None

  def get_corpus(self, target: str) -> Optional[Path]:
    """
    Get corpus for a target from cloud storage.

    Args:
        target: Target name

    Returns:
        Optional[Path]: Local corpus path or None if not found
    """
    if not self.storage_client:
      return None

    try:
      bucket = self.storage_client.bucket(self.experiment_bucket)
      # Look for corpus files with target name pattern
      blobs = bucket.list_blobs(prefix=f"{target}_")
      for blob in blobs:
        if blob.name.endswith('.corpus.zip'):
          # Download to local temp directory
          local_path = Path(f"/tmp/{target}_corpus.zip")
          blob.download_to_filename(local_path)
          return local_path
    except Exception as e:
      self.logger.error("Failed to get corpus for %s: %s", target, e)
    return None

  # Core Cloud Running Logic (migrated from old implementation)

  def _run_target_cloud(self, build_metadata: Dict[str, Any], target_name: str,
                        options: FuzzRunOptions, run_info: 'RunInfo') -> bool:
    """
    Run a fuzz target in the cloud using build metadata from CloudBuilder.

    Args:
        build_metadata: Build metadata from CloudBuilder
        target_name: Name of the target to run
        options: Fuzzing options
        run_info: RunInfo instance to update with results

    Returns:
        bool: True if run was successful
    """
    self.logger.info('Running %s in the cloud', target_name)

    # Extract information from build metadata
    generated_project = build_metadata.get('generated_project')
    if not generated_project or not isinstance(generated_project, str):
      raise ValueError(
          "Generated project name is required and must be a string")
    experiment_bucket = build_metadata.get('experiment_bucket',
                                           self.experiment_bucket)
    experiment_name = build_metadata.get('experiment_name',
                                         self.experiment_name)
    uid = build_metadata.get('uid', f"{experiment_name}-{uuid.uuid4()}")

    # Define cloud storage paths for running artifacts
    run_log_name = f'{uid}.run.log'
    run_log_path = f'gs://{experiment_bucket}/{run_log_name}'

    corpus_name = f'{uid}.corpus.zip'
    corpus_path = f'gs://{experiment_bucket}/{corpus_name}'

    coverage_name = f'{uid}.coverage'
    coverage_path = f'gs://{experiment_bucket}/{coverage_name}'

    reproducer_name = f'{uid}.reproducer'
    reproducer_path = f'gs://{experiment_bucket}/{reproducer_name}'

    # Update run_info with cloud paths
    run_info.log_path = run_log_path
    run_info.corpus_path = corpus_path
    run_info.coverage_report_path = coverage_path
    run_info.reproducer_path = reproducer_path

    # Build the command for target_experiment.py (running phase)
    command = self._build_cloud_run_command(
        generated_project, target_name, build_metadata.get('project_name', ''),
        run_log_path, coverage_path, reproducer_path, corpus_path, options)

    self.logger.info('Cloud run command: %s', command)

    # Execute with retry control
    oss_fuzz_dir = EnvUtils.get_oss_fuzz_dir()
    if not self._run_with_retry_control(command, oss_fuzz_dir):
      return False

    # Process cloud run results
    self._process_cloud_run_results(run_log_name, corpus_name, coverage_name,
                                    target_name,
                                    build_metadata.get('project_name',
                                                       ''), run_info)

    return True

  def _build_cloud_run_command(self, generated_project: str, target_name: str,
                               project_name: str, run_log_path: str,
                               coverage_path: str, reproducer_path: str,
                               corpus_path: str,
                               options: FuzzRunOptions) -> List[str]:
    """Build the command for cloud run execution (running phase)."""
    # Determine OSS-Fuzz checkout directory
    venv_dir = EnvUtils.get_venv_dir()

    # Build command focused on running, not building
    command = [
        f'{venv_dir}/bin/python3',
        'infra/build/functions/target_experiment.py',
        f'--project={generated_project}',
        f'--target={target_name}',
        f'--upload_output_log={run_log_path}',
        f'--upload_coverage={coverage_path}',
        f'--upload_reproducer={reproducer_path}',
        f'--upload_corpus={corpus_path}',
        f'--experiment_name={self.experiment_name}',
        f'--real_project={project_name}',
    ]

    # Add libfuzzer arguments for running
    libfuzzer_args = [
        '-print_final_stats=1',
        f'-max_total_time={options.duration_seconds or 3600}',
        '-len_control=0',
        f'-timeout={options.timeout_seconds or 25}',
    ]

    if not options.detect_leaks:
      libfuzzer_args.append('-detect_leaks=0')

    command += ['--'] + libfuzzer_args

    return command

  def _run_with_retry_control(self, command: List[str], cwd: str) -> bool:
    """Execute command with controllable retry and customized exponential
    backoff."""
    # Retry configuration (migrated from old implementation)
    max_attempts = 5
    retryable_errors = [
        ('RESOURCE_EXHAUSTED', lambda x: 5 * 2**x + random.randint(50, 90)),
        ('BrokenPipeError: [Errno 32] Broken pipe',
         lambda x: 5 * 2**x + random.randint(1, 5)),
        ('Service Unavailable', lambda x: 5 * 2**x + random.randint(1, 5)),
        ('You do not currently have an active account selected',
         lambda x: 5 * 2**x),
        ('gcloud crashed (OSError): unexpected end of data',
         lambda x: 5 * 2**x),
    ]

    for attempt_id in range(1, max_attempts + 1):
      try:
        subprocess.run(command,
                       check=True,
                       cwd=cwd,
                       capture_output=True,
                       text=True)
        return True
      except subprocess.CalledProcessError as e:
        # Replace \n for single log entry on cloud
        stdout = e.stdout.replace('\n', '\t') if e.stdout else ''
        stderr = e.stderr.replace('\n', '\t') if e.stderr else ''

        delay = next((delay_f(attempt_id)
                      for err, delay_f in retryable_errors
                      if err in stdout + stderr), 0)

        if not delay or attempt_id == max_attempts:
          self.logger.error('Failed to run cloud target, attempt %d:\n%s\n%s',
                            attempt_id, stdout, stderr)
          break

        self.logger.warning(
            'Failed to run cloud target, attempt %d, retry in %ds:\n'
            '%s\n%s', attempt_id, delay, stdout, stderr)
        time.sleep(delay)

    return False

  def _process_cloud_run_results(self, run_log_name: str, corpus_name: str,
                                 coverage_name: str, target_name: str,
                                 project_name: str, run_info: 'RunInfo'):
    """Process and download cloud run results."""
    if not self.storage_client:
      self.logger.warning("No storage client available for result processing")
      return

    bucket = self.storage_client.bucket(self.experiment_bucket)

    # Download run log
    run_log_local_path = f'/tmp/{target_name}_cloud_run.log'
    blob = bucket.blob(run_log_name)
    if blob.exists():
      self.logger.info('Downloading cloud run log: %s to %s, coverage_name: %s',
                       run_log_name, run_log_local_path, coverage_name)
      with open(run_log_local_path, 'wb') as f:
        blob.download_to_file(f)
      run_info.log_path = run_log_local_path

      # Parse libfuzzer logs for coverage and crash information
      with open(run_log_local_path, 'rb') as f:
        parse_result = self.parse_libfuzzer_logs(f, project_name)
        run_info.cov_pcs = parse_result.get('cov_pcs', 0)
        run_info.total_pcs = parse_result.get('total_pcs', 0)
        run_info.crashes = parse_result.get('crashes', False)
        run_info.crash_info = parse_result.get('crash_info', '')
    else:
      self.logger.warning('Cannot find cloud run log: %s', run_log_name)

    # Download corpus
    corpus_local_path = f'/tmp/{target_name}_cloud_corpus.zip'
    blob = bucket.blob(corpus_name)
    if blob.exists():
      with open(corpus_local_path, 'wb') as f:
        blob.download_to_file(f)
      run_info.corpus_path = corpus_local_path

    # TODO: Process coverage reports based on language
    # This would involve downloading and parsing textcov reports
    self.logger.info('Coverage processing not yet fully implemented for %s',
                     target_name)
