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
import traceback
import uuid
from collections import defaultdict, namedtuple
from typing import Any, Optional

from google.cloud import storage

from experiment import oss_fuzz_checkout, textcov
from experiment.benchmark import Benchmark
from experiment.fuzz_target_error import SemanticCheckResult
from experiment.workdir import WorkDirs
from llm_toolkit import code_fixer
from llm_toolkit.crash_triager import TriageResult
from llm_toolkit.models import DefaultModel

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

# The directory in the oss-fuzz image
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

ParseResult = namedtuple(
    'ParseResult',
    ['cov_pcs', 'total_pcs', 'crashes', 'crash_info', 'semantic_check_result'])


@dataclasses.dataclass
class BuildResult:
  """Results of compilation & link."""

  succeeded: bool = False
  errors: list[str] = dataclasses.field(default_factory=list)
  log_path: str = ''

  def to_dict(self):
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
  crash_info: str = ''
  triage: str = TriageResult.NOT_APPLICABLE
  semantic_check: SemanticCheckResult = SemanticCheckResult(
      SemanticCheckResult.NOT_APPLICABLE)

  def to_dict(self):
    return dataclasses.asdict(self)


class BuilderRunner:
  """Builder and runner."""

  # Regex for extract function name.
  FUNC_NAME = re.compile(r'(?:^|\s|\b)([\w:]+::)*(\w+)(?:<[^>]*>)?(?=\(|$)')
  # Regex for extract line number,
  LINE_NUMBER = re.compile(r':(\d+):')

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
        '-len_control=0',
        # Timeout per testcase.
        '-timeout=30',
        '-detect_leaks=0',
    ]

  def _get_minimum_func_name(self, func_sig: str) -> str:
    """Extracts the minimum function name from function signature,
    without name space, return type, params, templates."""
    pattern = (r'(?:[a-zA-Z_]\w*::)*([a-zA-Z_]\w*|operator[^(\s]*)(?:\s*<.*>)?'
               r'\s*\(')
    match = re.search(pattern, func_sig)
    if not match:
      return func_sig

    function_name = match.group(1).strip()
    return function_name.removeprefix('operator')

  def _contains_target_jvm_method(self, target_path: str) -> bool:
    """Validates if the LLM-generated code contains the target jvm methods."""
    signature = self.benchmark.function_signature

    # For test to harness approach, the target signature does not
    # exist, no need to do this pre-check
    if not signature or not '].' in signature:
      return True

    with open(target_path) as generated_code_file:
      code = generated_code_file.read()

    # This regex is used to identify legitimate Java variable names
    # or instance method calls (which could return a needed variable).
    # This is necessary because the method name of a Java method also
    # includes its parameter list in order to distinguish between
    # overloaded methods. Thus it need to use the regex to identify
    # if there are method calls with unknown variable names that match
    # the target method.
    base_arg_regex = r'[\s]*[a-zA-Z_$][a-zA-Z_$0-9(),.]*'
    name = signature.split('].')[1].split('(')[0]
    arg_count = len(signature.split('(')[1].split(')')[0].split(','))

    if '<init>' in name:
      # Always return true for Java constructors because it is not possible
      # to match all possible ways to call the constructors
      return True

    pattern = rf'({name}\({", ".join([base_arg_regex] * arg_count)}\))'
    match = re.search(pattern, ''.join(code.splitlines()).replace(' ', ''))

    return bool(match)

  def _contains_target_function(self, target_path: str) -> bool:
    """Validates if the LLM-generated code contains the target function."""
    with open(target_path) as generated_code_file:
      generated_code = generated_code_file.read()

    min_func_name = self._get_minimum_func_name(
        self.benchmark.function_signature)

    return min_func_name in generated_code

  def _contains_target_python_function(self, target_path: str) -> bool:
    """Validates if the LLM-generated code contains the target function for
    python projects."""
    with open(target_path) as generated_code_file:
      generated_code = generated_code_file.read()

    min_func_name = self.benchmark.function_signature.rsplit('.', 1)[-1]

    return min_func_name in generated_code

  def _contains_target_rust_function(self, target_path: str) -> bool:
    """Validates if the LLM-generated code contains the target function for
    rust projects."""
    with open(target_path) as generated_code_file:
      generated_code = generated_code_file.read()

    min_func_name = self._get_minimum_func_name(
        self.benchmark.function_signature)

    # Retrieve function name only with crate, triat, impl or mod tag
    min_func_name = min_func_name.rsplit('::', 1)[-1]
    min_func_name = min_func_name.rsplit('.', 1)[-1]

    return min_func_name in generated_code

  def _pre_build_check(self, target_path: str,
                       build_result: BuildResult) -> bool:
    """Checks the generated target before building and running it."""
    # No need to build the fuzz target if it does not contain the target
    # function.
    if self.benchmark.language == 'jvm':
      result = self._contains_target_jvm_method(target_path)
    elif self.benchmark.language == 'python':
      result = self._contains_target_python_function(target_path)
    elif self.benchmark.language == 'rust':
      result = self._contains_target_rust_function(target_path)
    else:
      # C/C++ pre-build check is done in agents.
      return True

    if not result:
      build_result.errors = [
          (f'The target function `{self.benchmark.function_signature}`'
           ' was not called by the fuzz target '
           '`LLVMFuzzerTestOneInput`.'
           'YOU MUST CALL FUNCTION '
           f'`{self.benchmark.function_signature}` INSIDE FUNCTION '
           '`LLVMFuzzerTestOneInput`.')
      ]
      logger.warning('Missing target function: %s does not contain %s',
                     target_path, self.benchmark.function_signature)

    return result

  def _parse_stacks_from_libfuzzer_logs(self,
                                        lines: list[str]) -> list[list[str]]:
    """Parses stack traces from libFuzzer logs."""
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

  def _parse_func_from_stacks(self, project_name: str,
                              stacks: list[list[str]]) -> dict:
    """Parses project functions from stack traces."""
    func_info = defaultdict(set)

    for stack in stacks:
      for line in stack:
        # Use 3 spaces to divide each line of crash info into four parts.
        # Only parse the fourth part, which includes the function name,
        # file path, and line number.
        parts = line.split(' ', 3)
        if len(parts) < 4:
          continue
        func_and_file_path = parts[3]
        if project_name not in func_and_file_path:
          continue
        func_name, _, file_path = func_and_file_path.partition(' /')
        if func_name == 'LLVMFuzzerTestOneInput':
          line_match = self.LINE_NUMBER.search(file_path)
          if line_match:
            line_number = int(line_match.group(1))
            func_info[func_name].add(line_number)
          else:
            logger.warning('Failed to parse line number from %s in project %s',
                           func_name, project_name)
          break
        if project_name in file_path:
          func_match = self.FUNC_NAME.search(func_name)
          line_match = self.LINE_NUMBER.search(file_path)
          if func_match and line_match:
            func_name = func_match.group(2)
            line_number = int(line_match.group(1))
            func_info[func_name].add(line_number)
          else:
            logger.warning(
                'Failed to parse function name from %s in project %s',
                func_name, project_name)

    return func_info

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
          if 'INITED' in line and 'cov: ' in line:
            initcov = int(line.split('cov: ')[1].split(' ft:')[0])
          elif 'DONE' in line and 'cov: ' in line:
            donecov = int(line.split('cov: ')[1].split(' ft:')[0])

    return initcov, donecov, lastround

  def _stack_func_is_of_testing_project(self, stack_frame: str) -> bool:
    return (bool(CRASH_STACK_WITH_SOURCE_INFO.match(stack_frame)) and
            LIBFUZZER_LOG_STACK_FRAME_LLVM not in stack_frame and
            LIBFUZZER_LOG_STACK_FRAME_LLVM2 not in stack_frame and
            LIBFUZZER_LOG_STACK_FRAME_CPP not in stack_frame)

  def _parse_libfuzzer_logs(self,
                            log_handle,
                            project_name: str,
                            check_cov_increase: bool = True) -> ParseResult:
    """Parses libFuzzer logs."""
    lines = None
    try:
      fuzzlog = log_handle.read(-1)
      # Some crashes can mess up the libfuzzer output and raise decode error.
      fuzzlog = fuzzlog.decode('utf-8', errors='ignore')
      lines = fuzzlog.split('\n')
    except MemoryError as e:
      # Some logs from abnormal fuzz targets are too large to be parsed.
      logger.error('%s is too large to parse: %s', log_handle.name, e)
      return ParseResult(0, 0, False, '',
                         SemanticCheckResult(SemanticCheckResult.LOG_MESS_UP))

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
      crash_func = self._parse_func_from_stacks(project_name, crash_stacks)
      crash_info = SemanticCheckResult.extract_crash_info(fuzzlog)

      # FP case 1: Common fuzz target errors.
      # Null-deref, normally indicating inadequate parameter initialization or
      # wrong function usage.
      if symptom == 'null-deref':
        return ParseResult(
            cov_pcs, total_pcs, True, crash_info,
            SemanticCheckResult(SemanticCheckResult.NULL_DEREF, symptom,
                                crash_stacks, crash_func))

      # Signal, normally indicating assertion failure due to inadequate
      # parameter initialization or wrong function usage.
      if symptom == 'signal':
        return ParseResult(
            cov_pcs, total_pcs, True, crash_info,
            SemanticCheckResult(SemanticCheckResult.SIGNAL, symptom,
                                crash_stacks, crash_func))

      # Exit, normally indicating the fuzz target exited in a controlled manner,
      # blocking its bug discovery.
      if symptom.endswith('fuzz target exited'):
        return ParseResult(
            cov_pcs, total_pcs, True, crash_info,
            SemanticCheckResult(SemanticCheckResult.EXIT, symptom, crash_stacks,
                                crash_func))

      # Fuzz target modified constants.
      if symptom.endswith('fuzz target overwrites its const input'):
        return ParseResult(
            cov_pcs, total_pcs, True, crash_info,
            SemanticCheckResult(SemanticCheckResult.OVERWRITE_CONST, symptom,
                                crash_stacks, crash_func))

      # OOM, normally indicating malloc's parameter is too large, e.g., because
      # of using parameter `size`.
      # TODO(dongge): Refine this, 1) Merge this with the other oom case found
      # from reproducer name; 2) Capture the actual number in (malloc(\d+)).
      if 'out-of-memory' in symptom or 'out of memory' in symptom:
        return ParseResult(
            cov_pcs, total_pcs, True, crash_info,
            SemanticCheckResult(SemanticCheckResult.FP_OOM, symptom,
                                crash_stacks, crash_func))

      # FP case 2: fuzz target crashes at init or first few rounds.
      if lastround is None or lastround <= EARLY_FUZZING_ROUND_THRESHOLD:
        # No cov line has been identified or only INITED round has been passed.
        # This is very likely the false positive cases.
        return ParseResult(
            cov_pcs, total_pcs, True, crash_info,
            SemanticCheckResult(SemanticCheckResult.FP_NEAR_INIT_CRASH, symptom,
                                crash_stacks, crash_func))

      # FP case 3: no func in 1st thread stack belongs to testing proj.
      if len(crash_stacks) > 0:
        first_stack = crash_stacks[0]
        for stack_frame in first_stack:
          if self._stack_func_is_of_testing_project(stack_frame):
            if 'LLVMFuzzerTestOneInput' in stack_frame:
              return ParseResult(
                  cov_pcs, total_pcs, True, crash_info,
                  SemanticCheckResult(SemanticCheckResult.FP_TARGET_CRASH,
                                      symptom, crash_stacks, crash_func))
            break

      return ParseResult(
          cov_pcs, total_pcs, True, crash_info,
          SemanticCheckResult(SemanticCheckResult.NO_SEMANTIC_ERR, symptom,
                              crash_stacks, crash_func))

    if check_cov_increase and initcov == donecov and lastround is not None:
      # Another error fuzz target case: no cov increase.
      # A special case is initcov == donecov == None, which indicates no
      # interesting inputs were found. This may happen if the target rejected
      # all inputs we tried.
      return ParseResult(
          cov_pcs, total_pcs, False, '',
          SemanticCheckResult(SemanticCheckResult.NO_COV_INCREASE))

    return ParseResult(cov_pcs, total_pcs, crashes, '',
                       SemanticCheckResult(SemanticCheckResult.NO_SEMANTIC_ERR))

  def build_and_run(
      self,
      generated_project: str,
      target_path: str,
      iteration: int,
      language: str,
      cloud_build_tags: Optional[list[str]] = None,
      trial: int = 0,
  ) -> tuple[BuildResult, Optional[RunResult]]:
    """Builds and runs the fuzz target for fuzzing."""
    del cloud_build_tags
    build_result = BuildResult()

    if not self._pre_build_check(target_path, build_result):
      logger.warning('Pre-build check failure: %s', build_result)
      return build_result, None

    try:
      return self.build_and_run_local(generated_project, target_path, iteration,
                                      build_result, language, trial)
    except Exception as err:
      logger.warning(
          'Error occurred when building and running fuzz target locally'
          '(attempt %d) %s: %s', iteration, err, traceback.format_exc())
      raise err

  def build_and_run_local(
      self,
      generated_project: str,
      target_path: str,
      iteration: int,
      build_result: BuildResult,
      language: str,
      trial: int = 0,
  ) -> tuple[BuildResult, Optional[RunResult]]:
    """Builds and runs the fuzz target locally for fuzzing."""
    project_name = self.benchmark.project
    benchmark_target_name = os.path.basename(target_path)
    project_target_name = os.path.basename(self.benchmark.target_path)
    benchmark_log_path = self.work_dirs.build_logs_target(
        benchmark_target_name, iteration)
    build_result.succeeded = self.build_target_local(target_path,
                                                     benchmark_log_path)
    if not build_result.succeeded:
      errors = code_fixer.extract_error_message(benchmark_log_path,
                                                project_target_name, language)
      build_result.errors = errors
      return build_result, None

    # TODO(Dongge): Split Builder and Runner:
    # Make the rest lines in an independent function.
    run_result = RunResult()

    run_log_path = os.path.join(self.work_dirs.run_logs, f'{trial:02d}.log')
    self.run_target_local(target_path, run_log_path)
    run_result.coverage, run_result.coverage_summary = (self.get_coverage_local(
        target_path, benchmark_target_name))

    run_result.log_path = run_log_path

    # Parse libfuzzer logs to get fuzz target runtime details.
    with open(run_log_path, 'rb') as f:
      # In many case JVM/python projects won't have much cov
      # difference in short running. Adding the flag for JVM/python
      # projects to temporary skip the checking of coverage change.
      # Also skipping for rust projects in initial implementation.
      flag = not self.benchmark.language in ['jvm', 'python', 'rust']
      run_result.cov_pcs, run_result.total_pcs, \
        run_result.crashes, run_result.crash_info, \
          run_result.semantic_check = \
            self._parse_libfuzzer_logs(f, project_name, flag)

    return build_result, run_result

  def run_target_local(self, target_path: str, log_path: str):
    """Runs a target locally using the base image and volume mounting."""
    base_project_name = self.benchmark.project
    target_filename = os.path.basename(target_path)
    target_name_without_ext = os.path.splitext(target_filename)[0]

    logger.info('Running target %s for project %s',
                target_name_without_ext, base_project_name)

    # Define host paths for artifacts
    build_dir_host = os.path.join(oss_fuzz_checkout.OSS_FUZZ_DIR, 'build')
    out_dir_host = os.path.join(build_dir_host, 'out', base_project_name)
    corpus_dir_host = self.work_dirs.corpus(target_filename)
    # Ensure host directories exist
    os.makedirs(out_dir_host, exist_ok=True)
    os.makedirs(corpus_dir_host, exist_ok=True)

    # Define container paths
    out_dir_container = '/out'
    corpus_dir_container = '/corpus' # Mount corpus to a dedicated dir

    # Command to run the helper script inside docker
    helper_command = [
        'python3', '/usr/local/bin/helper.py',
        'run_fuzzer',
        base_project_name,
        target_name_without_ext, # Specify the target
        '--corpus-dir', corpus_dir_container, # Use mapped corpus dir
        '--' # Separator for libfuzzer args
    ] + self._libfuzzer_args()

    # --- Docker Run Command --- #
    docker_command = [
        'docker', 'run',
        '--rm',
        '--privileged',
        '--shm-size=2g',
        '--platform', 'linux/amd64',
        '-i',
        # Environment variables (sanitizer is implicitly address for run_fuzzer)
        '-e', 'FUZZING_ENGINE=libfuzzer',
        '-e', 'SANITIZER=address',
        '-e', 'ARCHITECTURE=x86_64',
        '-e', f'PROJECT_NAME={base_project_name}',
        '-e', f'FUZZING_LANGUAGE={self.benchmark.language}',
        # Volume mounts
        '-v', f'{os.path.abspath(out_dir_host)}:{out_dir_container}:ro', # Mount /out read-only
        '-v', f'{os.path.abspath(corpus_dir_host)}:{corpus_dir_container}', # Mount corpus rw
        # Base Image Name (assuming address sanitizer build)
        f'gcr.io/oss-fuzz/{base_project_name}',
    ] + helper_command # Append the helper script command

    logger.debug('Run command: %s', ' '.join(docker_command))

    with open(log_path, 'w') as f:
      proc = sp.Popen(docker_command,
                      stdin=sp.DEVNULL,
                      stdout=f,
                      stderr=sp.STDOUT,
                      cwd=oss_fuzz_checkout.OSS_FUZZ_DIR)

      try:
        # Wait for the process to complete with a timeout
        proc.wait(timeout=self.run_timeout + 10) # Add buffer to timeout
      except sp.TimeoutExpired:
        logger.warning('Target %s timed out during fuzzing.', target_name_without_ext)
        # Kill the container if it timed out
        kill_command = ['docker', 'kill', proc.pid] # Need container ID, pid won't work
        # Getting container ID reliably is hard here, manual intervention might be needed
        # For now, just log the timeout
        pass
      except Exception as e:
        logger.error("Error during run_target_local Popen: %s", e)
        # Process might not have started correctly

    if proc.returncode != 0:
      logger.warning('********** Failed to run target %s (return code %d). Log: %s **********',
                     target_name_without_ext, proc.returncode, log_path)
    else:
      logger.info('Successfully run target %s.', target_name_without_ext)

  def build_target_local(
      self, target_path: str, # Path to the generated target file on host
      log_path: str,
      sanitizer: str = 'address') -> bool:
    """Builds a target using the base project image and volume mounting."""

    base_project_name = self.benchmark.project
    target_filename = os.path.basename(target_path)
    target_name_without_ext = os.path.splitext(target_filename)[0]

    logger.info('Building target %s for %s with %s using base image',
                target_filename, base_project_name, sanitizer)

    # We assume the base image (e.g., gcr.io/oss-fuzz/libxml2) exists.
    # We skip the specific image build step.

    # Define host paths for artifacts (relative to OSS_FUZZ_DIR)
    build_dir_host = os.path.join(oss_fuzz_checkout.OSS_FUZZ_DIR, 'build')
    out_dir_host = os.path.join(build_dir_host, 'out', base_project_name)
    work_dir_host = os.path.join(build_dir_host, 'work', base_project_name)
    os.makedirs(out_dir_host, exist_ok=True)
    os.makedirs(work_dir_host, exist_ok=True)

    # Define container paths
    src_dir_container = f'/src/{base_project_name}'
    target_file_container = os.path.join(src_dir_container, target_filename)
    out_dir_container = '/out'
    work_dir_container = '/work'

    # --- Docker Run Command --- #
    command = [
        'docker',
        'run',
        '--rm', # Clean up container after exit
        '--privileged',
        '--shm-size=2g',
        '--platform', 'linux/amd64',
        '-i',
        # Essential environment variables
        '-e', 'FUZZING_ENGINE=libfuzzer',
        '-e', f'SANITIZER={sanitizer}',
        '-e', 'ARCHITECTURE=x86_64',
        '-e', f'PROJECT_NAME={base_project_name}', # Use base project name
        '-e', f'FUZZING_LANGUAGE={self.benchmark.language}',
        # Volume mounts
        '-v', f'{os.path.abspath(target_path)}:{target_file_container}:ro', # Mount target read-only
        '-v', f'{os.path.abspath(out_dir_host)}:{out_dir_container}',
        '-v', f'{os.path.abspath(work_dir_host)}:{work_dir_container}',
        # Base Image Name
        f'gcr.io/oss-fuzz/{base_project_name}',
        # Command to execute within the container
        # Use helper.py to build the specific target
        'python3',
        '/usr/local/bin/helper.py',
        'build_fuzzer', # Changed from build_fuzzers
        base_project_name,
        target_name_without_ext, # Pass the specific target name
        f'--sanitizer={sanitizer}' # Pass sanitizer
    ]

    logger.debug('Build command: %s', ' '.join(command))

    with open(log_path, 'w+') as log_file:
      try:
        # Note: CWD should be appropriate if helper.py relies on relative paths,
        # but oss_fuzz_checkout.OSS_FUZZ_DIR is likely correct.
        sp.run(command,
               cwd=oss_fuzz_checkout.OSS_FUZZ_DIR,
               stdin=sp.DEVNULL,
               stdout=log_file,
               stderr=sp.STDOUT,
               check=True)
      except sp.CalledProcessError as e:
        logger.warning('Failed to build target %s for project %s with %s: %s',
                    target_filename, base_project_name, sanitizer, e)
        # Log the output for debugging
        log_file.seek(0)
        logger.warning("Build log output:\n%s", log_file.read())
        return False
      except FileNotFoundError as e:
        logger.error("Docker command not found. Is Docker installed and in PATH? Error: %s", e)
        return False

    logger.info('Successfully built target %s for project %s with %s', target_filename,
                base_project_name, sanitizer)
    return True

  def _get_coverage_text_filename(self, project_name: str) -> str:
    """Get the filename of the text coverage file. This is language
    dependent."""
    lang_to_textcov_basename = {
        'jvm': 'jacoco.xml',
        'python': 'all_cov.json',
        'c++': f'{self.benchmark.target_name}.covreport',
        'c': f'{self.benchmark.target_name}.covreport',
        'rust': f'{self.benchmark.target_name}.covreport',
    }
    # Use base project name for artifact directory
    base_project_name = self.benchmark.project
    return os.path.join(get_build_artifact_dir(base_project_name,
                                               'out'), 'textcov_reports',
                        lang_to_textcov_basename[self.benchmark.language])

  def _extract_local_textcoverage_data(self,
                                       project_name: str) -> textcov.Textcov:
    """Returns the textcoverage from a local coverage run."""
    local_textcov_location = self._get_coverage_text_filename(project_name)
    language_modes = {
        'jvm': 'r',
        'python': 'r',
        'c': 'rb',
        'c++': 'rb',
        'rust': 'rb',
    }
    with open(local_textcov_location,
              language_modes.get(self.benchmark.language, 'rb')) as f:
      if self.benchmark.language == 'jvm':
        new_textcov = textcov.Textcov.from_jvm_file(f)
      elif self.benchmark.language == 'python':
        new_textcov = textcov.Textcov.from_python_file(f)
      elif self.benchmark.language == 'rust':
        new_textcov = textcov.Textcov.from_rust_file(f)
      else:
        target_basename = os.path.basename(self.benchmark.target_path)
        new_textcov = textcov.Textcov.from_file(
            f,
            ignore_function_patterns=[
                # Don't include other functions defined in the target code.
                re.compile(r'^' + re.escape(target_basename) + ':')
            ])
      return new_textcov

  def get_coverage_local(
      self, target_path: str, # Path to the generated target file on host
      benchmark_target_name: str # Basename of the target file (e.g., 01.cpp)
  ) -> tuple[Optional[textcov.Textcov], Any]:
    """Generates coverage reports locally using the base image and volume mounting."""
    base_project_name = self.benchmark.project
    target_filename = os.path.basename(target_path)
    target_name_without_ext = os.path.splitext(target_filename)[0]

    logger.info('Extracting coverage for target %s for project %s',
                target_name_without_ext, base_project_name)

    # --- Remove the coverage build step --- #
    # No longer needed as we use the base coverage-instrumented build
    # Assuming the coverage build was done by a prior call to build_target_local
    # with sanitizer='coverage'. We need to ensure this happens.
    # TODO: Adjust workflow to ensure coverage build happens exactly once if needed.

    # Define host paths
    build_dir_host = os.path.join(oss_fuzz_checkout.OSS_FUZZ_DIR, 'build')
    out_dir_host = os.path.join(build_dir_host, 'out', base_project_name)
    corpus_dir_host = self.work_dirs.corpus(benchmark_target_name)
    # Ensure host directories exist (especially /out from previous build)
    if not os.path.isdir(out_dir_host):
        logger.error('Coverage build output directory not found: %s. Cannot generate coverage.', out_dir_host)
        return None, None
    os.makedirs(corpus_dir_host, exist_ok=True)

    # Define container paths
    src_dir_container = f'/src/{base_project_name}'
    target_file_container = os.path.join(src_dir_container, target_filename)
    out_dir_container = '/out'
    corpus_dir_container = '/corpus'

    # --- Docker Run Command for Coverage --- #
    helper_command = [
        'python3', '/usr/local/bin/helper.py',
        'coverage',
        base_project_name,
        '--fuzz-target', target_name_without_ext, # Specify the target
        '--corpus-dir', corpus_dir_container,    # Use mapped corpus dir
        '--no-serve',
        '--port', '', # Pass empty port as server is not needed
    ]
    if self.benchmark.language != 'c++':
        helper_command.append(f'--language={self.benchmark.language}')

    docker_command = [
        'docker', 'run',
        '--rm',
        '--privileged',
        '--shm-size=2g',
        '--platform', 'linux/amd64',
        '-i',
        # Environment variables
        '-e', 'FUZZING_ENGINE=libfuzzer',
        '-e', 'SANITIZER=coverage', # Explicitly set sanitizer
        '-e', 'ARCHITECTURE=x86_64',
        '-e', f'PROJECT_NAME={base_project_name}',
        '-e', f'FUZZING_LANGUAGE={self.benchmark.language}',
        # Volume mounts
        '-v', f'{os.path.abspath(target_path)}:{target_file_container}:ro', # Mount target source
        '-v', f'{os.path.abspath(out_dir_host)}:{out_dir_container}', # Mount /out (contains binary AND gets coverage reports)
        '-v', f'{os.path.abspath(corpus_dir_host)}:{corpus_dir_container}:ro', # Mount corpus read-only
        # Base Image Name (assuming coverage build exists/matches)
        f'gcr.io/oss-fuzz/{base_project_name}', # Use the same base image, SANITIZER env var selects build
    ] + helper_command

    logger.debug('Coverage command: %s', ' '.join(docker_command))
    log_path = os.path.join(self.work_dirs.build_logs, f'{target_name_without_ext}-coverage-gen.log')

    try:
        # Run the coverage generation command
        proc = sp.run(docker_command,
                      capture_output=True, # Capture output to check for errors
                      text=True,           # Decode output as text
                      cwd=oss_fuzz_checkout.OSS_FUZZ_DIR,
                      stdin=sp.DEVNULL,
                      check=True)
        logger.info("Coverage generation stdout:\n%s", proc.stdout)
        logger.info("Coverage generation stderr:\n%s", proc.stderr)

    except sp.CalledProcessError as e:
      logger.error('Failed to generate coverage for target %s project %s:\n%s\n%s',
                  target_name_without_ext, base_project_name, e.stdout, e.stderr)
      # Save log even on failure
      with open(log_path, 'w') as f:
          f.write("COMMAND:\n" + ' '.join(docker_command) + "\n\n")
          f.write("STDOUT:\n" + e.stdout + "\n\n")
          f.write("STDERR:\n" + e.stderr + "\n\n")
      return None, None
    except FileNotFoundError as e:
        logger.error("Docker command not found. Is Docker installed and in PATH? Error: %s", e)
        return None, None

    # Save successful log
    with open(log_path, 'w') as f:
        f.write("COMMAND:\n" + ' '.join(docker_command) + "\n\n")
        f.write("STDOUT:\n" + proc.stdout + "\n\n")
        f.write("STDERR:\n" + proc.stderr + "\n\n")

    # --- Extract results from HOST /build/out/<project> directory --- #
    # This part remains largely the same as it reads from the host path
    # where docker mounted /out

    # Get the local text coverage, which includes the specific lines
    # exercised in the target project.
    try:
        local_textcov = self._extract_local_textcoverage_data(base_project_name)
    except FileNotFoundError:
        logger.error('Coverage text report file not found after running coverage command. Check logs: %s', log_path)
        return None, None
    except Exception as e:
        logger.error('Error parsing coverage text report: %s', e)
        return None, None

    # Copy the code coverage report (HTML) to the results directory
    coverage_report_host_path = os.path.join(out_dir_host, 'report')
    if os.path.isdir(coverage_report_host_path):
        destination_coverage = self.work_dirs.code_coverage_report(
            benchmark_target_name)
        shutil.copytree(coverage_report_host_path, destination_coverage, dirs_exist_ok=True)
    else:
        logger.warning('Coverage HTML report directory not found at %s', coverage_report_host_path)

    # Copy textcov reports
    textcov_dir_host_path = os.path.join(out_dir_host, 'textcov_reports')
    if os.path.isdir(textcov_dir_host_path):
        dst_textcov = os.path.join(
            self.work_dirs.code_coverage_report(benchmark_target_name), 'textcov')
        shutil.copytree(textcov_dir_host_path, dst_textcov, dirs_exist_ok=True)
    else:
         logger.warning('Coverage textcov_reports directory not found at %s', textcov_dir_host_path)


    # Load summary.json
    coverage_summary = None
    coverage_summary_host_path = os.path.join(coverage_report_host_path, 'linux', 'summary.json')
    if os.path.isfile(coverage_summary_host_path):
        try:
            with open(coverage_summary_host_path) as f:
              coverage_summary = json.load(f)
        except Exception as e:
            logger.error('Failed to load coverage summary %s: %s', coverage_summary_host_path, e)
    else:
        logger.warning('Coverage summary.json not found at %s', coverage_summary_host_path)

    return local_textcov, coverage_summary


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
        # Service Unavailable.
        ('Service Unavailable', lambda x: 5 * 2**x + random.randint(1, 5)),
        # Temp workaround for issue #12.
        ('You do not currently have an active account selected',
         lambda x: 5 * 2**x),
        # Workaround for issue #85.
        ('gcloud crashed (OSError): unexpected end of data', lambda x: 5 * 2**x
        ),
    ]

    for attempt_id in range(1, CLOUD_EXP_MAX_ATTEMPT + 1):
      try:
        sp.run(*args, check=True, **kwargs)
        return True
      except sp.CalledProcessError as e:
        # Replace \n for single log entry on cloud.
        stdout = e.stdout.decode('utf-8').replace('\n', '\t')
        stderr = e.stderr.decode('utf-8').replace('\n', '\t')

        delay = next((delay_f(attempt_id)
                      for err, delay_f in retryable_errors
                      if err in stdout + stderr), 0)

        if not delay or attempt_id == CLOUD_EXP_MAX_ATTEMPT:
          logger.error('Failed to evaluate %s on cloud, attempt %d:\n%s\n%s',
                       os.path.realpath(target_path), attempt_id, stdout,
                       stderr)
          break

        logger.warning(
            'Failed to evaluate %s on cloud, attempt %d, retry in %ds:\n'
            '%s\n%s', os.path.realpath(target_path), attempt_id, delay, stdout,
            stderr)
        time.sleep(delay)
    logger.info('Evaluate %s on cloud.', os.path.realpath(target_path))

    return False

  def build_and_run(
      self,
      generated_project: str,
      target_path: str,
      iteration: int,
      language: str,
      cloud_build_tags: Optional[list[str]] = None,
      trial: int = 0,
  ) -> tuple[BuildResult, Optional[RunResult]]:
    """Builds and runs the fuzz target for fuzzing."""
    build_result = BuildResult()
    if not self._pre_build_check(target_path, build_result):
      logger.warning('Pre-build check failure: %s', build_result)
      return build_result, None

    try:
      return self.build_and_run_cloud(generated_project, target_path, iteration,
                                      build_result, language, cloud_build_tags,
                                      trial)
    except Exception as err:
      logger.warning(
          'Error occurred when building and running fuzz target on cloud'
          '(attempt %d) %s: %s', iteration, err, traceback.format_exc())
      traceback.print_exc()
      raise err

  def build_and_run_cloud(
      self,
      generated_project: str,
      target_path: str,
      iteration: int,
      build_result: BuildResult,
      language: str,
      cloud_build_tags: Optional[list[str]] = None,
      trial: int = 0,
  ) -> tuple[BuildResult, Optional[RunResult]]:
    """Builds and runs the fuzz target locally for fuzzing."""
    logger.info('Evaluating %s on cloud.', os.path.realpath(target_path))

    project_name = self.benchmark.project

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

    logger.info('Servie account key: %s',
                os.environ.get('GOOGLE_APPLICATION_CREDENTIALS'))
    command = [
        f'./{oss_fuzz_checkout.VENV_DIR}/bin/python3',
        'infra/build/functions/target_experiment.py',
        f'--project={generated_project}',
        f'--target={self.benchmark.target_name}',
        f'--upload_build_log={build_log_path}',
        f'--upload_output_log={run_log_path}',
        f'--upload_coverage={coverage_path}',
        f'--upload_reproducer={reproducer_path}',
        f'--upload_corpus={corpus_path}',
        f'--experiment_name={self.experiment_name}',
        f'--real_project={project_name}',
    ]

    # TODO(dongge): Reenable caching when build script is not modified.
    # Current caching is not applicable when OFG modifies the build script,
    # There is no simple way to check if the build script has been modified,
    # but this feature should be added later.
    # and fails to build the project (particularly with coverage sanitizer).
    # if oss_fuzz_checkout.ENABLE_CACHING and (
    #     oss_fuzz_checkout.is_image_cached(project_name, 'address') and
    #     oss_fuzz_checkout.is_image_cached(project_name, 'coverage')):
    #   logger.info('Using cached image for %s', project_name)
    #   command.append('--use_cached_image')

    #   # Overwrite the Dockerfile to be caching friendly
    #   # We hardcode 'address' here, but this is irrelevant and will be
    #   # overridden later via a Docker argument.
    #   oss_fuzz_checkout.rewrite_project_to_cached_project(
    #       project_name, generated_project, 'address')
    #   oss_fuzz_checkout.prepare_build(project_name, 'address',
    #                                   generated_project)

    if cloud_build_tags:
      command += ['--tags'] + cloud_build_tags
    command += ['--'] + self._libfuzzer_args()

    logger.info('Command: %s', command)

    if not self._run_with_retry_control(os.path.realpath(target_path),
                                        command,
                                        cwd=oss_fuzz_checkout.OSS_FUZZ_DIR):
      return build_result, None

    logger.info('Evaluated %s on cloud.', os.path.realpath(target_path))

    storage_client = storage.Client()
    bucket = storage_client.bucket(self.experiment_bucket)

    build_result.log_path = build_log_path

    generated_target_name = os.path.basename(target_path)
    with open(
        self.work_dirs.build_logs_target(generated_target_name, iteration),
        'wb') as f:
      blob = bucket.blob(build_log_name)
      if blob.exists():
        logger.info('Downloading cloud build log of %s: %s to %s',
                    os.path.realpath(target_path), build_log_name, f)
        blob.download_to_file(f)
      else:
        logger.warning('Cannot find cloud build log of %s: %s',
                       os.path.realpath(target_path), build_log_name)

    # TODO(Dongge): Split Builder and Runner:
    # Set build_result.succeeded based on existence of fuzz target binary.
    # Separate the rest lines into an independent function.
    run_log_path = os.path.join(self.work_dirs.run_logs, f'{trial:02d}.log')
    with open(run_log_path, 'wb') as f:
      blob = bucket.blob(run_log_name)
      if blob.exists():
        build_result.succeeded = True
        logger.info('Downloading cloud run log of %s: %s to %s',
                    os.path.realpath(target_path), run_log_name, f)
        blob.download_to_file(f)
      else:
        logger.warning('Cannot find cloud run log of %s: %s',
                       os.path.realpath(target_path), run_log_name)

    if not build_result.succeeded:
      errors = code_fixer.extract_error_message(
          self.work_dirs.build_logs_target(generated_target_name, iteration),
          os.path.basename(self.benchmark.target_path), language)
      build_result.errors = errors
      logger.info('Cloud evaluation of %s indicates a failure: %s',
                  os.path.realpath(target_path), errors)
      return build_result, None
    logger.info('Cloud evaluation of %s indicates a success.',
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
      # Download summary.json to our workdir.
      cov_summary_folder = os.path.join(
          self.work_dirs.code_coverage_report(generated_target_name),
          'report/linux/')
      os.makedirs(cov_summary_folder, exist_ok=True)
      coverage_summary_file = os.path.join(cov_summary_folder, 'summary.json')
      with open(coverage_summary_file, 'wb') as f:
        blob.download_to_file(f)

      # Load the coverage summary
      with open(coverage_summary_file, 'r') as f:
        run_result.coverage_summary = json.load(f)

    target_basename = os.path.basename(self.benchmark.target_path)

    # Load coverage reports.
    textcov_blob_path = self._get_cloud_textcov_path(coverage_name)
    if self.benchmark.language == 'jvm':
      blob = bucket.blob(textcov_blob_path)
      if blob.exists():
        with blob.open() as f:
          run_result.coverage = textcov.Textcov.from_jvm_file(f)
        self._copy_textcov_to_workdir(bucket, textcov_blob_path,
                                      generated_target_name)
    elif self.benchmark.language == 'python':
      blob = bucket.blob(textcov_blob_path)
      if blob.exists():
        with blob.open() as f:
          run_result.coverage = textcov.Textcov.from_python_file(f)
        self._copy_textcov_to_workdir(bucket, textcov_blob_path,
                                      generated_target_name)
    elif self.benchmark.language == 'rust':
      blob = bucket.blob(textcov_blob_path)
      if blob.exists():
        with blob.open() as f:
          run_result.coverage = textcov.Textcov.from_rust_file(f)
        self._copy_textcov_to_workdir(bucket, textcov_blob_path,
                                      generated_target_name)
    else:
      # C/C++
      blob = bucket.blob(textcov_blob_path)
      if blob.exists():
        with blob.open('rb') as f:
          run_result.coverage = textcov.Textcov.from_file(
              f,
              ignore_function_patterns=[
                  # Don't include other functions defined in the target code.
                  re.compile(r'^' + re.escape(target_basename) + ':')
              ])
        self._copy_textcov_to_workdir(bucket, textcov_blob_path,
                                      generated_target_name)

    # Parse libfuzzer logs to get fuzz target runtime details.
    with open(run_log_path, 'rb') as f:
      run_result.cov_pcs, run_result.total_pcs, \
        run_result.crashes, run_result.crash_info, \
          run_result.semantic_check = \
            self._parse_libfuzzer_logs(f, project_name)

    return build_result, run_result

  def _copy_textcov_to_workdir(self, bucket, textcov_blob_path: str,
                               generated_target_name: str) -> None:
    """Stores a given textcov blob into the workdir."""
    blob = bucket.blob(textcov_blob_path)
    textcov_dir = os.path.join(
        self.work_dirs.code_coverage_report(generated_target_name), 'textcov')
    os.makedirs(textcov_dir, exist_ok=True)
    textcov_dst = os.path.join(textcov_dir, os.path.basename(textcov_blob_path))
    with open(textcov_dst, 'wb') as f:
      blob.download_to_file(f)

  def _get_cloud_textcov_path(self, coverage_name: str) -> str:
    """Extracts textcov blob path for this benchmark."""
    if self.benchmark.language == 'jvm':
      return f'{coverage_name}/textcov_reports/jacoco.xml'
    if self.benchmark.language == 'python':
      return f'{coverage_name}/textcov_reports/all_cov.json'

    # For C/C++/Rust
    return (f'{coverage_name}/textcov_reports/{self.benchmark.target_name}'
            '.covreport')


def get_build_artifact_dir(generated_project: str, build_artifact: str) -> str:
  """
  Returns the |build_artifact| absolute directory path for |generated_project|.
  """
  return os.path.join(oss_fuzz_checkout.OSS_FUZZ_DIR, 'build', build_artifact,
                      generated_project)
