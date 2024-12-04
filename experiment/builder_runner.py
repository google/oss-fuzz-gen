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

  def _pre_build_check(self, target_path: str,
                       build_result: BuildResult) -> bool:
    """Checks the generated target before building and running it."""
    # No need to build the fuzz target if it does not contain the target
    # function.
    if self.benchmark.language == 'jvm':
      result = self._contains_target_jvm_method(target_path)
    elif self.benchmark.language == 'python':
      result = self._contains_target_python_function(target_path)
    else:
      result = self._contains_target_function(target_path)

    if not result:
      build_result.errors = [
          (f'The target function `{self.benchmark.function_signature}`'
           ' was not called by the fuzz target '
           '`LLVMFuzzerTestOneInput`.'
           'YOU MUST CALL FUNCTION '
           f'`{self.benchmark.function_signature}` INSIDE FUNCTION '
           '`LLVMFuzzerTestOneInput`.')
      ]
      logger.info('Missing target function: %s does not contain %s',
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
      cloud_build_tags: Optional[list[str]] = None
  ) -> tuple[BuildResult, Optional[RunResult]]:
    """Builds and runs the fuzz target for fuzzing."""
    del cloud_build_tags
    build_result = BuildResult()

    if not self._pre_build_check(target_path, build_result):
      return build_result, None

    try:
      return self.build_and_run_local(generated_project, target_path, iteration,
                                      build_result, language)
    except Exception as err:
      logger.warning(
          'Error occurred when building and running fuzz target locally'
          '(attempt %d) %s: %s', iteration, err, traceback.format_exc())
      raise err

  def build_and_run_local(
      self, generated_project: str, target_path: str, iteration: int,
      build_result: BuildResult,
      language: str) -> tuple[BuildResult, Optional[RunResult]]:
    """Builds and runs the fuzz target locally for fuzzing."""
    project_name = self.benchmark.project
    benchmark_target_name = os.path.basename(target_path)
    project_target_name = os.path.basename(self.benchmark.target_path)
    benchmark_log_path = self.work_dirs.build_logs_target(
        benchmark_target_name, iteration)
    build_result.succeeded = self.build_target_local(generated_project,
                                                     benchmark_log_path)

    # Copy err.log into work dir (Ignored for JVM projects)
    if language != 'jvm':
      try:
        shutil.copyfile(
            os.path.join(get_build_artifact_dir(generated_project, "workspace"),
                         'err.log'),
            self.work_dirs.error_logs_target(benchmark_target_name, iteration))
      except FileNotFoundError as e:
        logger.error('Cannot get err.log for %s: %s', generated_project, e)

    if not build_result.succeeded:
      errors = code_fixer.extract_error_message(benchmark_log_path,
                                                project_target_name, language)
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
      # In many case JVM/python projects won't have much cov
      # difference in short running. Adding the flag for JVM/python
      # projects to temporary skip the checking of coverage change.
      flag = not self.benchmark.language in ['jvm', 'python']
      run_result.cov_pcs, run_result.total_pcs, \
        run_result.crashes, run_result.crash_info, \
          run_result.semantic_check = \
            self._parse_libfuzzer_logs(f, project_name, flag)
      run_result.succeeded = not run_result.semantic_check.has_err

    return build_result, run_result

  def run_target_local(self, generated_project: str, benchmark_target_name: str,
                       log_path: str):
    """Runs a target in the fixed target directory."""
    # If target name is not overridden, use the basename of the target path
    # in the Dockerfile.
    logger.info('Running %s', generated_project)
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
        logger.info('%s timed out during fuzzing.', generated_project)
        # Try continuing and parsing the logs even in case of timeout.

    if proc.returncode != 0:
      logger.info('********** Failed to run %s. **********', generated_project)
    else:
      logger.info('Successfully run %s.', generated_project)

  def build_target_local(self,
                         generated_project: str,
                         log_path: str,
                         sanitizer: str = 'address') -> bool:
    """Builds a target with OSS-Fuzz."""

    logger.info('Building %s with %s', generated_project, sanitizer)

    if oss_fuzz_checkout.ENABLE_CACHING and oss_fuzz_checkout.is_image_cached(
        self.benchmark.project, sanitizer):
      logger.info('We should use cached instance.')
      # Rewrite for caching.
      oss_fuzz_checkout.rewrite_project_to_cached_project(
          self.benchmark.project, generated_project, sanitizer)

      # Prepare build
      oss_fuzz_checkout.prepare_build(self.benchmark.project, sanitizer,
                                      generated_project)

    else:
      logger.info('The project does not have any cache')

    # Build the image
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
        logger.info('Failed to build image for %s', generated_project)
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
        f'FUZZING_LANGUAGE={self.benchmark.language}',
        '-v',
        f'{outdir}:/out',
        '-v',
        f'{workdir}:/work',
        # Allows jcc to write err.log.
        # https://github.com/google/oss-fuzz/blob/090e0d6/infra/base-images/base-builder/jcc/jcc.go#L360
        '-v',
        f'{workspacedir}:/workspace',
    ]
    # Avoid permissions errors.
    os.makedirs(outdir, exist_ok=True)
    os.makedirs(workdir, exist_ok=True)
    os.makedirs(workspacedir, exist_ok=True)
    if self.benchmark.cppify_headers:
      command.extend(['-e', 'JCC_CPPIFY_PROJECT_HEADERS=1'])
    command.extend(['--entrypoint', '/bin/bash'])
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
    build_bash_command = ['-c', ' '.join(build_command)]
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
        logger.info('Failed to build fuzzer for %s with %s', generated_project,
                    sanitizer)
        return False

    logger.info('Successfully build fuzzer for %s with %s', generated_project,
                sanitizer)
    return True

  def _get_coverage_text_filename(self, project_name: str) -> str:
    """Get the filename of the text coverage file. This is language
    dependent."""
    lang_to_textcov_basename = {
        'jvm': 'jacoco.xml',
        'python': 'all_cov.json',
        'c++': f'{self.benchmark.target_name}.covreport',
        'c': f'{self.benchmark.target_name}.covreport'
    }

    return os.path.join(get_build_artifact_dir(project_name,
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
    }
    with open(local_textcov_location,
              language_modes.get(self.benchmark.language, 'rb')) as f:
      if self.benchmark.language == 'jvm':
        new_textcov = textcov.Textcov.from_jvm_file(f)
      elif self.benchmark.language == 'python':
        new_textcov = textcov.Textcov.from_python_file(f)
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
      self, generated_project: str,
      benchmark_target_name: str) -> tuple[Optional[textcov.Textcov], Any]:
    """Builds the generate project with coverage sanitizer, runs OSS-Fuzz
    coverage extraction and then returns the generated coverage reports, in
    the form of the text coverage as well as the summary.json."""
    sample_id = os.path.splitext(benchmark_target_name)[0]
    log_path = os.path.join(self.work_dirs.build_logs,
                            f'{sample_id}-coverage.log')
    logger.info('Building project for coverage')
    built_coverage = self.build_target_local(generated_project,
                                             log_path,
                                             sanitizer='coverage')
    if not built_coverage:
      logger.info('Failed to make coverage build for %s', generated_project)
      return None, None

    logger.info('Extracting coverage')
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
      logger.info('Failed to generate coverage for %s:\n%s\n%s',
                  generated_project, e.stdout, e.stderr)
      return None, None

    # Get the local text coverage, which includes the specific lines
    # exercised in the target project.
    local_textcov = self._extract_local_textcoverage_data(generated_project)

    # Copy the code coverage to a folder in the results directory so
    # the coverage can be displayed in the result HTML page.
    coverage_report = os.path.join(
        get_build_artifact_dir(generated_project, 'out'), 'report')
    destination_coverage = self.work_dirs.code_coverage_report(
        benchmark_target_name)
    shutil.copytree(coverage_report, destination_coverage, dirs_exist_ok=True)

    textcov_dir = os.path.join(get_build_artifact_dir(generated_project, 'out'),
                               'textcov_reports')
    dst_textcov = os.path.join(
        self.work_dirs.code_coverage_report(benchmark_target_name), 'textcov')
    shutil.copytree(textcov_dir, dst_textcov, dirs_exist_ok=True)

    coverage_summary = os.path.join(
        get_build_artifact_dir(generated_project, 'out'), 'report', 'linux',
        'summary.json')
    with open(coverage_summary) as f:
      coverage_summary = json.load(f)

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
          logger.error('Failed to evaluate %s on cloud, attempt %d:\n%s\n%s',
                       os.path.realpath(target_path), attempt_id, stdout,
                       stderr)
          break

        logger.warning(
            'Failed to evaluate %s on cloud, attempt %d, retry in %ds:\n'
            '%s\n%s', os.path.realpath(target_path), attempt_id, delay, stdout,
            stderr)
        time.sleep(delay)

    return False

  def build_and_run(
      self,
      generated_project: str,
      target_path: str,
      iteration: int,
      language: str,
      cloud_build_tags: Optional[list[str]] = None
  ) -> tuple[BuildResult, Optional[RunResult]]:
    """Builds and runs the fuzz target for fuzzing."""
    build_result = BuildResult()

    if not self._pre_build_check(target_path, build_result):
      return build_result, None

    try:
      return self.build_and_run_cloud(generated_project, target_path, iteration,
                                      build_result, language, cloud_build_tags)
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
      cloud_build_tags: Optional[list[str]] = None
  ) -> tuple[BuildResult, Optional[RunResult]]:
    """Builds and runs the fuzz target locally for fuzzing."""
    logger.info('Evaluating %s on cloud.', os.path.realpath(target_path))

    project_name = self.benchmark.project

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

    command = [
        f'./{oss_fuzz_checkout.VENV_DIR}/bin/python3',
        'infra/build/functions/target_experiment.py',
        f'--project={generated_project}',
        f'--target={self.benchmark.target_name}',
        f'--upload_build_log={build_log_path}',
        f'--upload_err_log={err_log_path}',
        f'--upload_output_log={run_log_path}',
        f'--upload_coverage={coverage_path}',
        f'--upload_reproducer={reproducer_path}',
        f'--upload_corpus={corpus_path}',
        f'--experiment_name={self.experiment_name}',
        f'--real_project={project_name}',
    ]

    if oss_fuzz_checkout.ENABLE_CACHING and (
        oss_fuzz_checkout.is_image_cached(project_name, 'address') and
        oss_fuzz_checkout.is_image_cached(project_name, 'coverage')):
      logger.info('Using cached image for %s', project_name)
      command.append('--use_cached_image')

      # Overwrite the Dockerfile to be caching friendly
      oss_fuzz_checkout.rewrite_project_to_cached_project_chronos(
          generated_project)

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

    # Ignored for JVM project since JVM project does not generate err.log
    if language != 'jvm':
      with open(
          self.work_dirs.error_logs_target(generated_target_name, iteration),
          'wb') as f:
        blob = bucket.blob(err_log_name)
        if blob.exists():
          logger.info('Downloading jcc error log of %s: %s to %s',
                      os.path.realpath(target_path), err_log_name, f)
          blob.download_to_file(f)
        else:
          logger.warning('Cannot find jcc error log of %s: %s',
                         os.path.realpath(target_path), err_log_name)

    with open(self.work_dirs.run_logs_target(generated_target_name, iteration),
              'wb') as f:
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
    with open(self.work_dirs.run_logs_target(generated_target_name, iteration),
              'rb') as f:
      run_result.cov_pcs, run_result.total_pcs, \
        run_result.crashes, run_result.crash_info, \
          run_result.semantic_check = \
            self._parse_libfuzzer_logs(f, project_name)
      run_result.succeeded = not run_result.semantic_check.has_err

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

    return (f'{coverage_name}/textcov_reports/{self.benchmark.target_name}'
            '.covreport')


def get_build_artifact_dir(generated_project: str, build_artifact: str) -> str:
  """
  Returns the |build_artifact| absolute directory path for |generated_project|.
  """
  return os.path.join(oss_fuzz_checkout.OSS_FUZZ_DIR, 'build', build_artifact,
                      generated_project)
