# Copyright 2024 Google LLC
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
Project local/cloud builder and runner.
"""
import dataclasses
import json
import logging
import os
import random
import re
import subprocess as sp
import time
import uuid
from typing import Any, Optional

from google.cloud import storage

from experiment import oss_fuzz_checkout, textcov
from experiment.benchmark import Benchmark
from experiment.workdir import WorkDirs
from llm_toolkit import code_fixer
from llm_toolkit.models import DefaultModel

# The directory in the oss-fuzz image
JCC_DIR = '/usr/local/bin'

RUN_TIMEOUT: int = 30
CLOUD_EXP_MAX_ATTEMPT = 5


@dataclasses.dataclass
class BuildResult:
  succeeded: bool = False
  errors: list[str] = dataclasses.field(default_factory=list)
  log_path: str = ''

  def dict(self):
    return dataclasses.asdict(self)


@dataclasses.dataclass
class RunResult:
  coverage_summary: dict = dataclasses.field(default_factory=dict)
  coverage: Optional[textcov.Textcov] = None
  log_path: str = ''
  corpus_path: str = ''
  coverage_report_path: str = ''

  def dict(self):
    return dataclasses.asdict(self)


class BuilderRunner:
  """Builder and runner."""

  def __init__(self,
               benchmark: Benchmark,
               work_dirs: WorkDirs,
               run_timeout: int = RUN_TIMEOUT,
               fixer_model_name: str = DefaultModel.name):
    self.benchmark = benchmark
    self.work_dirs = work_dirs
    self.run_timeout = run_timeout
    self.fixer_model_name = fixer_model_name

  def _libfuzzer_args(self) -> list[str]:
    return [
        '-print_final_stats=1',
        f'-max_total_time={self.run_timeout}',
        # Without this flag, libFuzzer only consider short inputs in short
        # experiments, which lowers the coverage for quick performance tests.
        '-len_control=0'
    ]

  def _get_minimum_func_name(self, func_sig: str) -> str:
    """Extracts the minimum function name from function signature,
    without name space, return type, params, templates."""
    pattern = r'(?:[a-zA-Z_]\w*::)*([a-zA-Z_]\w*)(?:\s*<.*>)?\s*\('
    match = re.search(pattern, func_sig)
    return match.group(1).strip() if match else func_sig

  def _contains_target_function(self, target_path: str) -> bool:
    """Validates if the LLM-generated code contains the target function."""
    with open(target_path) as generated_code_file:
      generated_code = generated_code_file.read()
    min_func_name = self._get_minimum_func_name(
        self.benchmark.function_signature)
    return min_func_name in generated_code

  def _pre_build_check(self, target_path: str,
                       build_result: BuildResult) -> bool:
    """Checks the generated target before building and running it."""
    # No need to build the fuzz target if it does not contain the target
    # function.
    if not self._contains_target_function(target_path):
      build_result.errors = [
          (f'The target function `{self.benchmark.function_signature}`'
           ' was not called by the fuzz target '
           '`LLVMFuzzerTestOneInput`.'
           'YOU MUST CALL FUNCTION '
           f'`{self.benchmark.function_signature}` INSIDE FUNCTION '
           '`LLVMFuzzerTestOneInput`.')
      ]
      print(f'Missing target function: {target_path} does not contain '
            f'{self.benchmark.function_signature}')
      return False
    return True

  def build_and_run(self, generated_project: str, target_path: str,
                    iteration: int) -> tuple[BuildResult, Optional[RunResult]]:
    """Builds and runs the fuzz target for fuzzing."""
    build_result = BuildResult()

    if not self._pre_build_check(target_path, build_result):
      return build_result, None

    benchmark_target_name = os.path.basename(target_path)
    build_result.succeeded = self.build_target_local(
        generated_project,
        self.work_dirs.build_logs_target(benchmark_target_name, iteration))
    if not build_result.succeeded:
      errors = code_fixer.extract_error_message(
          self.work_dirs.build_logs_target(benchmark_target_name, iteration))
      build_result.errors = errors
      return build_result, None

    run_result = RunResult()

    self.run_target_local(generated_project, benchmark_target_name,
                          self.work_dirs.run_logs_target(benchmark_target_name))
    run_result.coverage, run_result.coverage_summary = (self.get_coverage_local(
        generated_project, benchmark_target_name))
    return build_result, run_result

  def run_target_local(self, generated_project: str, benchmark_target_name: str,
                       log_path: str):
    """Runs a target in the fixed target directory."""
    # If target name is not overridden, use the basename of the target path
    # in the Dockerfile.
    print(f'Running {generated_project}')
    corpus_dir = self.work_dirs.corpus(benchmark_target_name)
    command = [
        'python3', 'infra/helper.py', 'run_fuzzer', '--corpus-dir', corpus_dir,
        generated_project, self.benchmark.target_name, '--'
    ] + self._libfuzzer_args()

    with open(log_path, 'w') as f:
      proc = sp.Popen(command,
                      stdin=sp.DEVNULL,
                      stdout=f,
                      stderr=sp.STDOUT,
                      cwd=oss_fuzz_checkout.OSS_FUZZ_DIR)

      # TODO(ochang): Handle the timeout exception.
      try:
        proc.wait(timeout=self.run_timeout + 5)
      except sp.TimeoutExpired:
        print(f'{generated_project} timed out during fuzzing.')
        # Try continuing and parsing the logs even in case of timeout.

    if proc.returncode != 0:
      print(f'********** Failed to run {generated_project}. **********')
    else:
      print(f'Successfully run {generated_project}.')

  def build_target_local(self,
                         generated_project: str,
                         log_path: str,
                         sanitizer: str = 'address') -> bool:
    """Builds a target with OSS-Fuzz."""
    print(f'Building {generated_project} with {sanitizer}')
    command = [
        'docker', 'build', '-t', f'gcr.io/oss-fuzz/{generated_project}',
        os.path.join(oss_fuzz_checkout.OSS_FUZZ_DIR, 'projects',
                     generated_project)
    ]
    with open(log_path, 'w+') as log_file:
      try:
        sp.run(command,
               cwd=oss_fuzz_checkout.OSS_FUZZ_DIR,
               stdin=sp.DEVNULL,
               stdout=log_file,
               stderr=sp.STDOUT,
               check=True)
      except sp.CalledProcessError:
        print(f'Failed to build image for {generated_project}')
        return False

    outdir = get_outdir(generated_project)
    command = [
        'docker',
        'run',
        '--rm',
        '--privileged',
        '--shm-size=2g',
        '--platform',
        'linux/amd64',
        '-i',
        '-e',
        'FUZZING_ENGINE=libfuzzer',
        '-e',
        f'SANITIZER={sanitizer}',
        '-e',
        'ARCHITECTURE=x86_64',
        '-e',
        f'PROJECT_NAME={generated_project}',
        '-e',
        f'CXX={JCC_DIR}/clang++-jcc',
        '-e',
        f'CC={JCC_DIR}/clang-jcc',
        '-e',
        'FUZZING_LANGUAGE=c++',
        '-v',
        f'{outdir}:/out',
        '-v',
        f'{get_workdir(generated_project)}:/work',
    ]
    os.makedirs(outdir, exist_ok=True)  # Avoid permissions errors.
    if self.benchmark.cppify_headers:
      command.extend(['-e', 'JCC_CPPIFY_PROJECT_HEADERS=1'])
    command.append(f'gcr.io/oss-fuzz/{generated_project}')

    if self.benchmark.commit:
      # TODO(metzman): Try to use build_specified_commit here.
      build_command = []
      for repo, commit in self.benchmark.commit.items():
        build_command += [
            'git', '-C', repo, 'fetch', '--unshallow', '-f', '||', 'true', '&&'
        ]
        build_command += ['git', '-C', repo, 'checkout', commit, '-f', '&&']
      build_command.extend(['compile', '&&', 'chmod', '777', '-R', '/out/*'])
      build_bash_command = ['/bin/bash', '-c', ' '.join(build_command)]
      command.extend(build_bash_command)
    with open(log_path, 'w+') as log_file:
      try:
        sp.run(command,
               cwd=oss_fuzz_checkout.OSS_FUZZ_DIR,
               stdin=sp.DEVNULL,
               stdout=log_file,
               stderr=sp.STDOUT,
               check=True)
      except sp.CalledProcessError:
        print(f'Failed to run {generated_project} with {sanitizer}')
        return False

    print(f'Successfully run {generated_project} with {sanitizer}')
    return True

  def get_coverage_local(
      self, generated_project: str,
      benchmark_target_name: str) -> tuple[Optional[textcov.Textcov], Any]:
    """Get coverage."""
    sample_id = os.path.splitext(benchmark_target_name)[0]
    log_path = os.path.join(self.work_dirs.build_logs,
                            f'{sample_id}-coverage.log')
    built_coverage = self.build_target_local(generated_project,
                                             log_path,
                                             sanitizer='coverage')
    if not built_coverage:
      print(f'Failed to make coverage build for {generated_project}')
      return None, None

    corpus_dir = self.work_dirs.corpus(benchmark_target_name)
    command = [
        'python3',
        'infra/helper.py',
        'coverage',
        '--corpus-dir',
        corpus_dir,
        '--fuzz-target',
        self.benchmark.target_name,
        '--no-serve',
        '--port',
        '',
        generated_project,
    ]

    try:
      sp.run(command,
             capture_output=True,
             cwd=oss_fuzz_checkout.OSS_FUZZ_DIR,
             stdin=sp.DEVNULL,
             check=True)
    except sp.CalledProcessError as e:
      print(f'Failed to generate coverage for {generated_project}:\n'
            f'{e.stdout}\n'
            f'{e.stderr}')
      return None, None

    local_textcov_location = os.path.join(
        oss_fuzz_checkout.OSS_FUZZ_DIR, 'build', 'out', generated_project,
        'textcov_reports', f'{self.benchmark.target_name}.covreport')
    target_basename = os.path.basename(self.benchmark.target_path)
    with open(local_textcov_location) as f:
      new_textcov = textcov.Textcov.from_file(
          f,
          ignore_function_patterns=[
              # Don't include other functions defined in the target code.
              re.compile(r'^' + re.escape(target_basename) + ':')
          ])

    coverage_summary = os.path.join(oss_fuzz_checkout.OSS_FUZZ_DIR, 'build',
                                    'out', generated_project, 'report', 'linux',
                                    'summary.json')
    with open(coverage_summary) as f:
      coverage_summary = json.load(f)

    return new_textcov, coverage_summary


class CloudBuilderRunner(BuilderRunner):
  """Cloud BuilderRunner."""
  _RETRYABLE_ERRORS = [
      # As mentioned in pr #100.
      'RESOURCE_EXHAUSTED',
      # Temp workaround for issue #12.
      'You do not currently have an active account selected',
      # Workaround for issue #85.
      'gcloud crashed (OSError): unexpected end of data',
  ]

  def __init__(self, *args, experiment_name: str, experiment_bucket: str,
               **kwargs):
    self.experiment_name = experiment_name
    self.experiment_bucket = experiment_bucket
    super().__init__(*args, **kwargs)

  def build_and_run(self, generated_project: str, target_path: str,
                    iteration: int) -> tuple[BuildResult, Optional[RunResult]]:
    build_result = BuildResult()
    if not self._pre_build_check(target_path, build_result):
      return build_result, None

    print(f'Evaluating {os.path.realpath(target_path)} on cloud.')

    uid = self.experiment_name + str(uuid.uuid4())
    run_log_name = f'{uid}.run.log'
    run_log_path = f'gs://{self.experiment_bucket}/{run_log_name}'

    build_log_name = f'{uid}.build.log'
    build_log_path = f'gs://{self.experiment_bucket}/{build_log_name}'

    corpus_name = f'{uid}.corpus.zip'
    corpus_path = f'gs://{self.experiment_bucket}/{corpus_name}'

    coverage_name = f'{uid}.coverage'
    coverage_path = f'gs://{self.experiment_bucket}/{coverage_name}'

    for attempt_id in range(1, CLOUD_EXP_MAX_ATTEMPT + 1):
      try:
        sp.run([
            f'./{oss_fuzz_checkout.VENV_DIR}/bin/python3',
            'infra/build/functions/target_experiment.py',
            f'--project={generated_project}',
            f'--target={self.benchmark.target_name}',
            f'--upload_build_log={build_log_path}',
            f'--upload_output_log={run_log_path}',
            f'--upload_corpus={corpus_path}',
            f'--upload_coverage={coverage_path}',
            f'--experiment_name={self.experiment_name}', '--'
        ] + self._libfuzzer_args(),
               capture_output=True,
               check=True,
               cwd=oss_fuzz_checkout.OSS_FUZZ_DIR)
        break
      except sp.CalledProcessError as e:
        # Replace \n for single log entry on cloud.
        stdout = e.stdout.decode('utf-8').replace('\n', '\t')
        stderr = e.stderr.decode('utf-8').replace('\n', '\t')

        captured_error = next(
            (err for err in self._RETRYABLE_ERRORS if err in stdout + stderr),
            '')
        if captured_error and attempt_id < CLOUD_EXP_MAX_ATTEMPT:
          delay = 5 * 2**attempt_id
          if captured_error == 'RESOURCE_EXHAUSTED':
            # Add random jitter in case of exceeding request per minute quota.
            delay += random.randint(50, 90)

          logging.warning(
              'Failed to evaluate %s on cloud, attempt %d:\n%s\n%s\n'
              'Retry in %ds...', os.path.realpath(target_path), attempt_id,
              stdout, stderr, delay)
          time.sleep(delay)
        else:
          logging.error('Failed to evaluate %s on cloud, attempt %d:\n%s\n%s',
                        os.path.realpath(target_path), attempt_id, stdout,
                        stderr)
          return build_result, None

    print(f'Evaluated {os.path.realpath(target_path)} on cloud.')

    storage_client = storage.Client()
    bucket = storage_client.bucket(self.experiment_bucket)

    build_result.log_path = build_log_path

    generated_target_name = os.path.basename(target_path)
    with open(
        self.work_dirs.build_logs_target(generated_target_name, iteration),
        'wb') as f:
      blob = bucket.blob(build_log_name)
      if blob.exists():
        print(f'Downloading cloud build log of {os.path.realpath(target_path)}:'
              f' {build_log_name} to {f}')
        blob.download_to_file(f)
      else:
        print(f'Cannot find cloud build log of {os.path.realpath(target_path)} '
              f':{build_log_name}')

    with open(self.work_dirs.run_logs_target(generated_target_name), 'wb') as f:
      blob = bucket.blob(run_log_name)
      if blob.exists():
        build_result.succeeded = True
        print(f'Downloading cloud run log of {os.path.realpath(target_path)}:'
              f' {run_log_name} to {f}')
        blob.download_to_file(f)
      else:
        print(f'Cannot find cloud run log of {os.path.realpath(target_path)} '
              f':{run_log_name}')

    if not build_result.succeeded:
      errors = code_fixer.extract_error_message(
          self.work_dirs.build_logs_target(generated_target_name, iteration))
      build_result.errors = errors
      print(f'Cloud evaluation of {os.path.realpath(target_path)} indicates a '
            f'failure: {errors}')
      return build_result, None
    print(f'Cloud evaluation of {os.path.realpath(target_path)} indicates a '
          'success.')

    corpus_dir = self.work_dirs.corpus(generated_target_name)
    with open(os.path.join(corpus_dir, 'corpus.zip'), 'wb') as f:
      blob = bucket.blob(corpus_name)
      if blob.exists():
        blob.download_to_file(f)

    run_result = RunResult(corpus_path=corpus_path,
                           coverage_report_path=coverage_path,
                           log_path=run_log_path)
    blob = bucket.blob(f'{coverage_name}/report/linux/summary.json')
    if blob.exists():
      with blob.open() as f:
        run_result.coverage_summary = json.load(f)

    target_basename = os.path.basename(self.benchmark.target_path)
    blob = bucket.blob(
        f'{coverage_name}/textcov_reports/{self.benchmark.target_name}'
        '.covreport')
    if blob.exists():
      with blob.open() as f:
        run_result.coverage = textcov.Textcov.from_file(
            f,
            ignore_function_patterns=[
                # Don't include other functions defined in the target code.
                re.compile(r'^' + re.escape(target_basename) + ':')
            ])

    return build_result, run_result


# TODO(metzman): Finish this.
FUZZ_TARGET_MAGIC = b'ochangdonggeliumetzmanfuzzer'


def find_generated_fuzz_target(directory):
  for root, _, files in os.walk(directory):
    for filename in files:
      filepath = os.path.join(root, filename)
      with open(filepath, 'rb') as fp:
        data = fp.read()
      if FUZZ_TARGET_MAGIC in data:
        return filepath
  return None


def get_outdir(generated_project):
  return os.path.join(oss_fuzz_checkout.OSS_FUZZ_DIR, 'build', 'out',
                      generated_project)


def get_workdir(generated_project):
  return os.path.join(oss_fuzz_checkout.OSS_FUZZ_DIR, 'build', 'work',
                      generated_project)
