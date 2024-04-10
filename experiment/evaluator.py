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
LLM-generated project Evaluator.
"""
import dataclasses
import json
import os
import re
import shutil
import traceback
from typing import Optional

from google.cloud import storage

from experiment import builder_runner, oss_fuzz_checkout, textcov
from experiment.benchmark import Benchmark
from experiment.builder_runner import BuildResult, RunResult
from experiment.fuzz_target_error import SemanticCheckResult
from experiment.workdir import WorkDirs
from llm_toolkit import code_fixer

LLM_FIX_LIMIT = 5

LIBFUZZER_MODULES_LOADED_REGEX = re.compile(
    r'^INFO:\s+Loaded\s+\d+\s+(modules|PC tables)\s+\((\d+)\s+.*\).*')
LIBFUZZER_COV_REGEX = re.compile(r'.*cov: (\d+) ft:')
LIBFUZZER_CRASH_TYPE_REGEX = re.compile(r'.*Test unit written to.*')
LIBFUZZER_COV_LINE_PREFIX = re.compile(r'^#(\d+)')
LIBFUZZER_STACK_FRAME_LINE_PREFIX = re.compile(r'^\s+#\d+')
CRASH_EXCLUSIONS = re.compile(r'.*(slow-unit-|timeout-|leak-|oom-).*')
CRASH_STACK_WITH_SOURCE_INFO = re.compile(r'in.*:\d+:\d+$')

OSS_FUZZ_COVERAGE_BUCKET = 'oss-fuzz-coverage'

LIBFUZZER_LOG_STACK_FRAME_LLVM = '/src/llvm-project/compiler-rt'
LIBFUZZER_LOG_STACK_FRAME_CPP = '/usr/local/bin/../include/c++'

EARLY_FUZZING_ROUND_THRESHOLD = 3


@dataclasses.dataclass
class Result:
  """Evaluation result."""
  compiles: bool = False
  crashes: bool = False
  coverage: float = 0.0
  line_coverage_diff: float = 0.0
  coverage_report_path: str = ''
  reproducer_path: str = ''
  # Gramatically correct but has false positive or no cov increase at all.
  is_semantic_error: bool = False
  semantic_error: str = ''

  def dict(self):
    return dataclasses.asdict(self)


def load_existing_textcov(project: str) -> textcov.Textcov:
  """Loads existing textcovs."""
  storage_client = storage.Client.create_anonymous_client()
  bucket = storage_client.bucket(OSS_FUZZ_COVERAGE_BUCKET)
  blobs = storage_client.list_blobs(bucket,
                                    prefix=f'{project}/textcov_reports/',
                                    delimiter='/')
  # Iterate through all blobs first to get the prefixes (i.e. "subdirectories").
  for blob in blobs:
    continue

  if not blobs.prefixes:  # type: ignore
    # No existing coverage reports.
    raise RuntimeError(f'No existing coverage reports for {project}')

  # Find the latest generated textcov date.
  latest_dir = sorted(blobs.prefixes)[-1]  # type: ignore
  blobs = storage_client.list_blobs(bucket, prefix=latest_dir)

  # Download and merge them.
  existing_textcov = textcov.Textcov()
  for blob in blobs:
    if not blob.name.endswith('.covreport'):
      continue

    print(f'Loading existing textcov from {blob.name}')
    with blob.open() as f:
      existing_textcov.merge(textcov.Textcov.from_file(f))

  return existing_textcov


def load_existing_coverage_summary(project: str) -> dict:
  """Load existing summary.json."""
  storage_client = storage.Client.create_anonymous_client()
  bucket = storage_client.bucket(OSS_FUZZ_COVERAGE_BUCKET)
  blobs = storage_client.list_blobs(bucket,
                                    prefix=f'{project}/reports/',
                                    delimiter='/')
  # Iterate through all blobs first to get the prefixes (i.e. "subdirectories").
  for blob in blobs:
    continue

  if not blobs.prefixes:  # type: ignore
    # No existing coverage reports.
    raise RuntimeError(f'No existing coverage reports for {project}')

  latest_dir = sorted(blobs.prefixes)[-1]  # type: ignore
  blob = bucket.blob(f'{latest_dir}linux/summary.json')
  print(f'Loading existing summary.json from {blob.name}')
  with blob.open() as f:
    return json.load(f)


def _compute_total_lines_without_fuzz_targets(
    coverage_summary: dict, fuzz_target_base_name: str) -> int:
  """Counts the total number of lines excluding the fuzz target."""
  # TODO(dongge): Exclude all fuzz targets if there are multiple.
  return sum([
      f['summary']['lines']['count']
      for f in coverage_summary['data'][0]['files']
      if fuzz_target_base_name not in f['filename']
  ])


def _rectify_docker_tag(docker_tag: str) -> str:
  # Replace "::" and any character not \w, _, or . with "-".
  valid_docker_tag = re.sub(r'::', '-', docker_tag)
  valid_docker_tag = re.sub(r'[^\w_.]', '-', valid_docker_tag)
  # Docker fails with tags containing -_ or _-.
  valid_docker_tag = re.sub(r'[-_]{2,}', '-', valid_docker_tag)
  return valid_docker_tag


# TODO(Dongge): Make this universally available.
class _Logger:
  """Log evaluation progress."""

  def __init__(
      self,
      status_path: str,
  ):
    self._log = open(os.path.join(status_path, 'log.txt'), 'w')
    self._result_path = os.path.join(status_path, 'result.json')

  def log(self, *args, **kwargs):
    print(*args, *kwargs)
    print(*args, *kwargs, file=self._log)
    self._log.flush()

  def return_result(self, result: Result):
    with open(self._result_path, 'w') as f:
      json.dump(result.dict(), f)

    return result


class Evaluator:
  """Target evaluator."""

  def __init__(self, runner: builder_runner.BuilderRunner, benchmark: Benchmark,
               work_dirs: WorkDirs):
    self.builder_runner = runner
    self.benchmark = benchmark
    self.work_dirs = work_dirs

  def build_log_path(self, generated_target_name: str, iteration: int):
    return os.path.join(self.work_dirs.run_logs,
                        f'{generated_target_name}-F{iteration}.log')

  def run_log_path(self, generated_target_name: str):
    return os.path.join(self.work_dirs.run_logs, f'{generated_target_name}.log')

  def create_ossfuzz_project(self, name: str, target_file: str) -> str:
    """Creates an OSS-Fuzz project with the generated target."""
    generated_project_path = os.path.join(oss_fuzz_checkout.OSS_FUZZ_DIR,
                                          'projects', name)
    if os.path.exists(generated_project_path):
      print(f'Project {generated_project_path} already exists.')
      return name

    existing_project_path = os.path.join(oss_fuzz_checkout.OSS_FUZZ_DIR,
                                         'projects', self.benchmark.project)

    shutil.copytree(existing_project_path, generated_project_path)
    shutil.copyfile(
        target_file,
        os.path.join(generated_project_path, os.path.basename(target_file)))
    with open(os.path.join(generated_project_path, 'Dockerfile'), 'a') as f:
      f.write(f'\nCOPY {os.path.basename(target_file)} '
              f'{self.benchmark.target_path}\n')
    return name

  def check_target(self, ai_binary, target_path: str) -> Optional[Result]:
    # Print out exceptions from multiprocessing.Pool.
    try:
      return self.do_check_target(ai_binary, target_path)
    except BaseException:
      traceback.print_exc()
      return None

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
            LIBFUZZER_LOG_STACK_FRAME_CPP not in stack_frame)

  def _parse_libfuzzer_logs(
      self, log_handle,
      logger: _Logger) -> tuple[int, int, bool, SemanticCheckResult]:
    """Parses libFuzzer logs."""
    lines = None
    try:
      fuzzlog = log_handle.read(-1)
      # Some crashes can mess up the libfuzzer output and raise decode error.
      fuzzlog = fuzzlog.decode('utf-8', errors='ignore')
      lines = fuzzlog.split('\n')
    except MemoryError as e:
      # Some logs from abnormal fuzz targets are too large to be parsed.
      logger.log('%s is too large to parse: %s', log_handle.name, e)
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
        crashes = True
        continue

    initcov, donecov, lastround = self._parse_fuzz_cov_info_from_libfuzzer_logs(
        lines)

    # NOTE: Crashes from incorrect fuzz targets will not be counted finally.

    if crashes:
      symptom = SemanticCheckResult.extract_symptom(fuzzlog)
      crash_stacks = self._parse_stacks_from_libfuzzer_logs(lines)

      # FP case 1: fuzz target crashes at init or first few rounds.
      if lastround is None or lastround <= EARLY_FUZZING_ROUND_THRESHOLD:
        # No cov line has been identified or only INITED round has been passed.
        # This is very likely the false positive cases.
        return cov_pcs, total_pcs, True, \
               SemanticCheckResult(SemanticCheckResult.FP_NEAR_INIT_CRASH,\
                             symptom, crash_stacks)

      # FP case 2: 1st func of the 1st thread stack is in fuzz target.
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
          return cov_pcs, total_pcs, True, SemanticCheckResult(
              SemanticCheckResult.NO_COV_INCREASE)

    return cov_pcs, total_pcs, crashes, SemanticCheckResult(
        SemanticCheckResult.NO_SEMANTIC_ERR)

  def _evaluate_generated_fuzz_target(
      self, generated_oss_fuzz_project: str, target_path: str,
      generated_target_name: str, iteration: int, logger: _Logger
  ) -> tuple[BuildResult, Optional[RunResult], int, int, bool,
             SemanticCheckResult]:
    """Evaluates the generated fuzz target."""
    build_result, run_result = self.builder_runner.build_and_run(
        generated_oss_fuzz_project, target_path, iteration)

    if not build_result.succeeded:
      # Clear the variables for case that fuzz/build err <=> before/after fix.
      return build_result, run_result, 0, 0, False, SemanticCheckResult(
          SemanticCheckResult.NOT_APPLICABLE)

    # Parse libfuzzer logs to get fuzz target runtime details.
    with open(self.work_dirs.run_logs_target(generated_target_name, iteration),
              'rb') as f:
      cov_pcs, total_pcs, crashes, semantic_error = self._parse_libfuzzer_logs(
          f, logger)

    return build_result, run_result, cov_pcs, total_pcs, crashes, semantic_error

  def _fix_generated_fuzz_target(self, ai_binary: str,
                                 generated_oss_fuzz_project: str,
                                 target_path: str, iteration: int,
                                 build_result: BuildResult,
                                 semantic_error: SemanticCheckResult):
    """Fixes the generated fuzz target."""
    if build_result.succeeded:
      error_desc, errors = semantic_error.get_error_info()
    else:
      error_desc, errors = None, build_result.errors
    code_fixer.llm_fix(ai_binary, target_path, self.benchmark, iteration,
                       error_desc, errors, self.builder_runner.fixer_model_name)
    shutil.copyfile(
        target_path,
        os.path.join(oss_fuzz_checkout.OSS_FUZZ_DIR, 'projects',
                     generated_oss_fuzz_project, os.path.basename(target_path)))

  def do_check_target(self, ai_binary: str, target_path: str) -> Result:
    """Builds and runs a target."""
    generated_target_name = os.path.basename(target_path)
    sample_id = os.path.splitext(generated_target_name)[0]
    generated_oss_fuzz_project = f'{self.benchmark.id}-{sample_id}'
    generated_oss_fuzz_project = _rectify_docker_tag(generated_oss_fuzz_project)
    self.create_ossfuzz_project(generated_oss_fuzz_project, target_path)

    status_path = os.path.join(self.work_dirs.status, sample_id)
    os.makedirs(status_path, exist_ok=True)

    logger = _Logger(status_path)

    # Try building and running the new target.

    # TODO: Log build failure.
    # TODO: Log run success/failure.

    # Loop of evaluating and fixing fuzz target.
    llm_fix_count = 0
    while True:
      # 1. Evaluating generated driver.
      (build_result, run_result, cov_pcs, total_pcs, crashes,
       semantic_error) = self._evaluate_generated_fuzz_target(
           generated_oss_fuzz_project, target_path, generated_target_name,
           llm_fix_count, logger)

      gen_succ = build_result.succeeded and not semantic_error.has_err
      if gen_succ:
        # Successfully generate the fuzz target.
        break

      if llm_fix_count >= LLM_FIX_LIMIT:
        # Not fix since the fix limit is reached.
        break

      # 2. Fixing generated driver.
      llm_fix_count += 1
      logger.log(f'Fixing {target_path} with '
                 f'{self.builder_runner.fixer_model_name}, '
                 f'attempt {llm_fix_count}.')
      self._fix_generated_fuzz_target(ai_binary, generated_oss_fuzz_project,
                                      target_path, llm_fix_count, build_result,
                                      semantic_error)

    # Logs and returns the result.
    if gen_succ:
      logger.log(f'Successfully built {target_path} with '
                 f'{self.builder_runner.fixer_model_name} in '
                 f'{llm_fix_count} iterations.')
    else:
      logger.log(f'Failed to fix {target_path} with '
                 f'{self.builder_runner.fixer_model_name} in '
                 f'{llm_fix_count} iterations.')
      return logger.return_result(
          Result(False, False, 0.0, 0.0, '', '', False, semantic_error.type))

    if (not run_result or run_result.coverage_summary is None or
        run_result.coverage is None):
      logger.log(f'Warning: No run_result in {generated_oss_fuzz_project}.')
      return logger.return_result(
          Result(True, crashes, 0.0, 0.0, '', '', False, semantic_error.type))

    if semantic_error.has_err:
      logger.log(
          f'Warning: {semantic_error.type} in {generated_oss_fuzz_project}.')
      return logger.return_result(
          Result(True, crashes, 0.0, 0.0, run_result.coverage_report_path,
                 run_result.reproducer_path, semantic_error.has_err,
                 semantic_error.type))

    # Gets line coverage (diff) details.
    coverage_summary = self._load_existing_coverage_summary()
    total_lines = _compute_total_lines_without_fuzz_targets(
        coverage_summary, generated_target_name)
    if total_pcs:
      coverage_percent = cov_pcs / total_pcs
    else:
      logger.log(f'Warning: total_pcs == 0 in {generated_oss_fuzz_project}.')
      coverage_percent = 0.0

    existing_textcov = self._load_existing_textcov()
    run_result.coverage.subtract_covered_lines(existing_textcov)

    if total_lines:
      coverage_diff = run_result.coverage.covered_lines / total_lines
    else:
      logger.log(f'Warning: total_lines == 0 in {generated_oss_fuzz_project}.')
      coverage_diff = 0.0

    logger.log(f'Result for {generated_oss_fuzz_project}: crashes={crashes}, '
               f'coverage={coverage_percent} ({cov_pcs}/{total_pcs}), '
               f'coverage diff={coverage_diff} '
               f'({run_result.coverage.covered_lines}/{total_lines})')
    return logger.return_result(
        Result(True, crashes, coverage_percent, coverage_diff,
               run_result.coverage_report_path, run_result.reproducer_path,
               semantic_error.has_err, semantic_error.type))

  def _load_existing_coverage_summary(self) -> dict:
    """Load existing summary.json."""
    return load_existing_coverage_summary(self.benchmark.project)

  def _load_existing_textcov(self) -> textcov.Textcov:
    """Loads existing textcovs."""
    return load_existing_textcov(self.benchmark.project)
