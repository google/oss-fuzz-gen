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
import shutil
import subprocess as sp
import time
import uuid
from typing import Any, Optional

from google.cloud import storage

from experiment import oss_fuzz_checkout, textcov
from experiment.benchmark import Benchmark
from experiment.fuzz_target_error import SemanticCheckResult
from experiment.workdir import WorkDirs
from llm_toolkit import code_fixer
from llm_toolkit.models import DefaultModel

# The directory in the oss-fuzz image
JCC_DIR = '/usr/local/bin'

RUN_TIMEOUT: int = 30
CLOUD_EXP_MAX_ATTEMPT = 5

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


@dataclasses.dataclass
class BuildResult:
  """Results of compilation & link."""

  succeeded: bool = False
  errors: list[str] = dataclasses.field(default_factory=list)
  log_path: str = ''

  def dict(self):
    return dataclasses.asdict(self)


@dataclasses.dataclass
class RunResult:
  """Checked results of conducting short-term fuzzing."""

  succeeded: bool = False
  coverage_summary: dict = dataclasses.field(default_factory=dict)
  coverage: Optional[textcov.Textcov] = None
  log_path: str = ''
  corpus_path: str = ''
  coverage_report_path: str = ''
  reproducer_path: str = ''
  cov_pcs: int = 0
  total_pcs: int = 0
  crashes: bool = False
  semantic_check: SemanticCheckResult = SemanticCheckResult(
      SemanticCheckResult.NOT_APPLICABLE)

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

  def _parse_stacks_from_libfuzzer_logs(self,
                                        lines: list[str]) -> list[list[str]]:
    """Parse stack traces from libFuzzer logs."""
    # TODO (dongge): Use stack parsing from ClusterFuzz.
    # There can have over one thread stack in a log.
    stacks = []

    # A stack -> a sequence of stack frame lines.
    stack, stack_parsing = [], False
    for line in lines:
      is_stack_frame_line = LIBFUZZER_STACK_FRAME_LINE_PREFIX.match(
          line) is not None
      if (not stack_parsing) and is_stack_frame_line:
        # First line.
        stack_parsing = True
        stack = [line.strip()]
      elif stack_parsing and is_stack_frame_line:
        # Middle line(s).
        stack.append(line.strip())
      elif stack_parsing and (not is_stack_frame_line):
        # Last line.
        stack_parsing = False
        stacks.append(stack)

    # Last stack.
    if stack_parsing:
      stacks.append(stack)

    return stacks

  def _parse_fuzz_cov_info_from_libfuzzer_logs(
      self,
      lines: list[str]) -> tuple[Optional[int], Optional[int], Optional[int]]:
    """Parses cov of INITED & DONE, and round number from libFuzzer logs."""
    initcov, donecov, lastround = None, None, None

    for line in lines:
      if line.startswith('#'):
        # Parses cov line to get the round number.
        match = LIBFUZZER_COV_LINE_PREFIX.match(line)
        roundno = int(match.group(1)) if match else None

        if roundno is not None:
          lastround = roundno
          if 'INITED' in line:
            initcov = int(line.split('cov: ')[1].split(' ft:')[0])
          elif 'DONE' in line:
            donecov = int(line.split('cov: ')[1].split(' ft:')[0])

    return initcov, donecov, lastround

  def _stack_func_is_of_testing_project(self, stack_frame: str) -> bool:
    return (bool(CRASH_STACK_WITH_SOURCE_INFO.match(stack_frame)) and
            LIBFUZZER_LOG_STACK_FRAME_LLVM not in stack_frame and
            LIBFUZZER_LOG_STACK_FRAME_LLVM2 not in stack_frame and
            LIBFUZZER_LOG_STACK_FRAME_CPP not in stack_frame)

  def _parse_libfuzzer_logs(
      self, log_handle) -> tuple[int, int, bool, SemanticCheckResult]:
    """Parses libFuzzer logs."""
    lines = None
    try:
      fuzzlog = log_handle.read(-1)
      # Some crashes can mess up the libfuzzer output and raise decode error.
      fuzzlog = fuzzlog.decode('utf-8', errors='ignore')
      lines = fuzzlog.split('\n')
    except MemoryError as e:
      # Some logs from abnormal fuzz targets are too large to be parsed.
      logging.error('%s is too large to parse: %s', log_handle.name, e)
      return 0, 0, False, SemanticCheckResult(SemanticCheckResult.LOG_MESS_UP)

    cov_pcs, total_pcs, crashes = 0, 0, False

    for line in lines:
      m = LIBFUZZER_MODULES_LOADED_REGEX.match(line)
      if m:
        total_pcs = int(m.group(2))
        continue

      m = LIBFUZZER_COV_REGEX.match(line)
      if m:
        cov_pcs = int(m.group(1))
        continue

      m = LIBFUZZER_CRASH_TYPE_REGEX.match(line)
      if m and not CRASH_EXCLUSIONS.match(line):
        # TODO(@happy-qop): Handling oom, slow cases in semantic checks & fix.
        crashes = True
        continue

    initcov, donecov, lastround = self._parse_fuzz_cov_info_from_libfuzzer_logs(
        lines)

    # NOTE: Crashes from incorrect fuzz targets will not be counted finally.

    if crashes:
      symptom = SemanticCheckResult.extract_symptom(fuzzlog)
      crash_stacks = self._parse_stacks_from_libfuzzer_logs(lines)

      # FP case 1: Common fuzz target errors.
      # Null-deref, normally indicating inadequate parameter initialization or
      # wrong function usage.
      if symptom == 'null-deref':
        return cov_pcs, total_pcs, True, SemanticCheckResult(
            SemanticCheckResult.NULL_DEREF, symptom, crash_stacks)

      # Signal, normally indicating assertion failure due to inadequate
      # parameter initialization or wrong function usage.
      if symptom == 'signal':
        return cov_pcs, total_pcs, True, SemanticCheckResult(
            SemanticCheckResult.SIGNAL, symptom, crash_stacks)

      # FP case 2: fuzz target crashes at init or first few rounds.
      if lastround is None or lastround <= EARLY_FUZZING_ROUND_THRESHOLD:
        # No cov line has been identified or only INITED round has been passed.
        # This is very likely the false positive cases.
        return cov_pcs, total_pcs, True, \
               SemanticCheckResult(SemanticCheckResult.FP_NEAR_INIT_CRASH,\
                             symptom, crash_stacks)

      # FP case 3: 1st func of the 1st thread stack is in fuzz target.
      if len(crash_stacks) > 0:
        first_stack = crash_stacks[0]
        # Check the first stack frame of the first stack only.
        for stack_frame in first_stack[:1]:
          if self._stack_func_is_of_testing_project(stack_frame):
            if 'LLVMFuzzerTestOneInput' in stack_frame:
              return cov_pcs, total_pcs, True, \
                     SemanticCheckResult(SemanticCheckResult.FP_TARGET_CRASH,\
                                   symptom, crash_stacks)
            break

    else:
      # Another error fuzz target case: no cov increase.
      if initcov is not None and donecov is not None:
        if initcov == donecov:
          return cov_pcs, total_pcs, False, SemanticCheckResult(
              SemanticCheckResult.NO_COV_INCREASE)

    return cov_pcs, total_pcs, crashes, SemanticCheckResult(
        SemanticCheckResult.NO_SEMANTIC_ERR)

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
    # Copy err.log into work dir.
    try:
      shutil.copyfile(
          os.path.join(get_build_artifact_dir(generated_project, "workspace"),
                       'err.log'),
          self.work_dirs.error_logs_target(benchmark_target_name, iteration))
    except FileNotFoundError as e:
      logging.error('Cannot get err.log for %s: %s', generated_project, e)
    if not build_result.succeeded:
      errors = code_fixer.extract_error_message(
          self.work_dirs.build_logs_target(benchmark_target_name, iteration))
      build_result.errors = errors
      return build_result, None

    run_result = RunResult()

    self.run_target_local(
        generated_project, benchmark_target_name,
        self.work_dirs.run_logs_target(benchmark_target_name, iteration))
    run_result.coverage, run_result.coverage_summary = (self.get_coverage_local(
        generated_project, benchmark_target_name))

    # Parse libfuzzer logs to get fuzz target runtime details.
    with open(self.work_dirs.run_logs_target(benchmark_target_name, iteration),
              'rb') as f:
      run_result.cov_pcs, run_result.total_pcs, run_result.crashes, \
                run_result.semantic_check = self._parse_libfuzzer_logs(f)
      run_result.succeeded = not run_result.semantic_check.has_err

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

    outdir = get_build_artifact_dir(generated_project, 'out')
    workdir = get_build_artifact_dir(generated_project, 'work')
    workspacedir = get_build_artifact_dir(generated_project, 'workspace')
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
        f'{workdir}:/work',
        # Allows jcc to write err.log.
        # From https://github.com/google/oss-fuzz/blob/090e0d6/infra/base-images/base-builder/jcc/jcc.go#L360
        '-v',
        f'{workspacedir}:/workspace',
    ]
    # Avoid permissions errors.
    os.makedirs(outdir, exist_ok=True)
    os.makedirs(workdir, exist_ok=True)
    os.makedirs(workspacedir, exist_ok=True)
    if self.benchmark.cppify_headers:
      command.extend(['-e', 'JCC_CPPIFY_PROJECT_HEADERS=1'])
    command.append(f'gcr.io/oss-fuzz/{generated_project}')

    pre_build_command = []
    post_build_command = []

    # Cleanup mounted dirs.
    pre_build_command.extend(
        ['rm', '-rf', '/out/*', '/work/*', '/workspace/*', '&&'])

    if self.benchmark.commit:
      # TODO(metzman): Try to use build_specified_commit here.
      for repo, commit in self.benchmark.commit.items():
        pre_build_command.extend([
            'git', '-C', repo, 'fetch', '--unshallow', '-f', '||', 'true', '&&'
        ])
        pre_build_command.extend(
            ['git', '-C', repo, 'checkout', commit, '-f', '&&'])
      post_build_command.extend(['&&', 'chmod', '777', '-R', '/out/*'])

    build_command = pre_build_command + ['compile'] + post_build_command
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

  def __init__(self, *args, experiment_name: str, experiment_bucket: str,
               **kwargs):
    self.experiment_name = experiment_name
    self.experiment_bucket = experiment_bucket
    super().__init__(*args, **kwargs)

  @staticmethod
  def _run_with_retry_control(target_path: str, *args, **kwargs) -> bool:
    """sp.run() with controllable retry and customized exponential backoff."""
    # List of (error_str, exp_backoff_func).
    retryable_errors = [
        # As mentioned in pr #100.
        ('RESOURCE_EXHAUSTED', lambda x: 5 * 2**x + random.randint(50, 90)),
        # As mentioned in pr #151.
        ('BrokenPipeError: [Errno 32] Broken pipe',
         lambda x: 5 * 2**x + random.randint(1, 5)),
        # Temp workaround for issue #12.
        ('You do not currently have an active account selected',
         lambda x: 5 * 2**x),
        # Workaround for issue #85.
        ('gcloud crashed (OSError): unexpected end of data', lambda x: 5 * 2**x
        ),
    ]

    for attempt_id in range(1, CLOUD_EXP_MAX_ATTEMPT + 1):
      try:
        sp.run(*args, capture_output=True, check=True, **kwargs)
        return True
      except sp.CalledProcessError as e:
        # Replace \n for single log entry on cloud.
        stdout = e.stdout.decode('utf-8').replace('\n', '\t')
        stderr = e.stderr.decode('utf-8').replace('\n', '\t')

        delay = next((delay_f(attempt_id)
                      for err, delay_f in retryable_errors
                      if err in stdout + stderr), 0)

        if not delay or attempt_id == CLOUD_EXP_MAX_ATTEMPT:
          logging.error('Failed to evaluate %s on cloud, attempt %d:\n%s\n%s',
                        os.path.realpath(target_path), attempt_id, stdout,
                        stderr)
          break

        logging.warning(
            'Failed to evaluate %s on cloud, attempt %d, retry in %ds:\n'
            '%s\n%s', os.path.realpath(target_path), attempt_id, delay, stdout,
            stderr)
        time.sleep(delay)

    return False

  def build_and_run(self, generated_project: str, target_path: str,
                    iteration: int) -> tuple[BuildResult, Optional[RunResult]]:
    build_result = BuildResult()
    if not self._pre_build_check(target_path, build_result):
      return build_result, None

    logging.info('Evaluating %s on cloud.', os.path.realpath(target_path))

    uid = self.experiment_name + str(uuid.uuid4())
    run_log_name = f'{uid}.run.log'
    run_log_path = f'gs://{self.experiment_bucket}/{run_log_name}'

    build_log_name = f'{uid}.build.log'
    build_log_path = f'gs://{self.experiment_bucket}/{build_log_name}'

    err_log_name = f'{uid}.err.log'
    err_log_path = f'gs://{self.experiment_bucket}/{err_log_name}'

    corpus_name = f'{uid}.corpus.zip'
    corpus_path = f'gs://{self.experiment_bucket}/{corpus_name}'

    coverage_name = f'{uid}.coverage'
    coverage_path = f'gs://{self.experiment_bucket}/{coverage_name}'

    reproducer_name = f'{uid}.reproducer'
    reproducer_path = f'gs://{self.experiment_bucket}/{reproducer_name}'

    if not self._run_with_retry_control(
        os.path.realpath(target_path),
        [
            f'./{oss_fuzz_checkout.VENV_DIR}/bin/python3',
            'infra/build/functions/target_experiment.py',
            f'--project={generated_project}',
            f'--target={self.benchmark.target_name}',
            f'--upload_build_log={build_log_path}',
            f'--upload_err_log={err_log_path}',
            f'--upload_output_log={run_log_path}',
            f'--upload_corpus={corpus_path}',
            f'--upload_coverage={coverage_path}',
            f'--upload_reproducer={reproducer_path}',
            f'--experiment_name={self.experiment_name}', '--'
        ] + self._libfuzzer_args(),
        cwd=oss_fuzz_checkout.OSS_FUZZ_DIR):
      return build_result, None

    logging.info('Evaluated %s on cloud.', os.path.realpath(target_path))

    storage_client = storage.Client()
    bucket = storage_client.bucket(self.experiment_bucket)

    build_result.log_path = build_log_path

    generated_target_name = os.path.basename(target_path)
    with open(
        self.work_dirs.build_logs_target(generated_target_name, iteration),
        'wb') as f:
      blob = bucket.blob(build_log_name)
      if blob.exists():
        logging.info('Downloading cloud build log of %s: %s to %s',
                     os.path.realpath(target_path), build_log_name, f)
        blob.download_to_file(f)
      else:
        logging.warning('Cannot find cloud build log of %s: %s',
                        os.path.realpath(target_path), build_log_name)

    with open(
        self.work_dirs.error_logs_target(generated_target_name, iteration),
        'wb') as f:
      blob = bucket.blob(err_log_name)
      if blob.exists():
        logging.info('Downloading jcc error log of %s: %s to %s',
                     os.path.realpath(target_path), err_log_name, f)
        blob.download_to_file(f)
      else:
        logging.warning('Cannot find jcc error log of %s: %s',
                        os.path.realpath(target_path), err_log_name)

    with open(self.work_dirs.run_logs_target(generated_target_name, iteration),
              'wb') as f:
      blob = bucket.blob(run_log_name)
      if blob.exists():
        build_result.succeeded = True
        logging.info('Downloading cloud run log of %s: %s to %s',
                     os.path.realpath(target_path), run_log_name, f)
        blob.download_to_file(f)
      else:
        logging.warning('Cannot find cloud run log of %s: %s',
                        os.path.realpath(target_path), run_log_name)

    if not build_result.succeeded:
      errors = code_fixer.extract_error_message(
          self.work_dirs.build_logs_target(generated_target_name, iteration))
      build_result.errors = errors
      logging.info('Cloud evaluation of %s indicates a failure: %s',
                   os.path.realpath(target_path), errors)
      return build_result, None
    logging.info('Cloud evaluation of %s indicates a success.',
                 os.path.realpath(target_path))

    corpus_dir = self.work_dirs.corpus(generated_target_name)
    with open(os.path.join(corpus_dir, 'corpus.zip'), 'wb') as f:
      blob = bucket.blob(corpus_name)
      if blob.exists():
        blob.download_to_file(f)

    run_result = RunResult(corpus_path=corpus_path,
                           coverage_report_path=coverage_path,
                           reproducer_path=reproducer_path,
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

    # Parse libfuzzer logs to get fuzz target runtime details.
    with open(self.work_dirs.run_logs_target(generated_target_name, iteration),
              'rb') as f:
      run_result.cov_pcs, run_result.total_pcs, run_result.crashes, \
                  run_result.semantic_check = self._parse_libfuzzer_logs(f)
      run_result.succeeded = not run_result.semantic_check.has_err

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


def get_build_artifact_dir(generated_project: str, build_artifact: str) -> str:
  """
  Returns the |build_artifact| absolute directory path for |generated_project|.
  """
  return os.path.join(oss_fuzz_checkout.OSS_FUZZ_DIR, 'build', build_artifact,
                      generated_project)
