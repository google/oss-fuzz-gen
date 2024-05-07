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

OSS_FUZZ_COVERAGE_BUCKET = 'oss-fuzz-coverage'


@dataclasses.dataclass
class Result:
  """Evaluation result."""
  compiles: bool = False
  crashes: bool = False
  coverage: float = 0.0
  line_coverage_diff: float = 0.0
  coverage_report_path: str = ''
  reproducer_path: str = ''
  # Grammatically correct but has false positive or no cov increase at all.
  is_semantic_error: bool = False
  semantic_error: str = ''
  # Deprecated renamed fields. Keeping them for backward compatibility.
  # TODO https://github.com/google/oss-fuzz-gen/issues/215
  is_driver_fuzz_err: bool = dataclasses.field(kw_only=True, default=False)
  driver_fuzz_err: str = dataclasses.field(kw_only=True, default='')

  def __post_init__(self, *args, **kwargs):  # pylint: disable=unused-argument
    if self.is_driver_fuzz_err:
      self.is_semantic_error = self.is_driver_fuzz_err
    if self.driver_fuzz_err:
      self.semantic_error = self.driver_fuzz_err

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

    # Fix public java class name in target_file
    if self.benchmark.language == 'jvm':
      with open(target_file, 'r') as file:
        code = file.read()

      new = os.path.basename(self.benchmark.target_path).replace('.java', '')
      code = code.replace('public class Fuzz', f'public class {new}')

      with open(target_file, 'w') as file:
        file.write(code)

    # Copy generated fuzzers to generated_project_path
    shutil.copyfile(
        target_file,
        os.path.join(generated_project_path, os.path.basename(target_file)))

    # Add additional statement in dockerfile to overwrite with generated fuzzer
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

  def _fix_generated_fuzz_target(self, ai_binary: str,
                                 generated_oss_fuzz_project: str,
                                 target_path: str, iteration: int,
                                 build_result: BuildResult,
                                 run_result: Optional[RunResult],
                                 logger: _Logger):
    """Fixes the generated fuzz target."""
    if build_result.succeeded:
      if run_result:
        error_desc, errors = run_result.semantic_check.get_error_info()
      else:
        logger.log(f'Warning: Build succeed but no run_result in '
                   f'{generated_oss_fuzz_project}.')
        error_desc, errors = '', []
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
      build_result, run_result = self.builder_runner.build_and_run(
          generated_oss_fuzz_project, target_path, llm_fix_count)

      gen_succ = build_result.succeeded and run_result and run_result.succeeded
      if gen_succ or llm_fix_count >= LLM_FIX_LIMIT:
        # Exit cond 1: successfully generate the fuzz target.
        # Exit cond 2: fix limit is reached.
        break

      # 2. Fixing generated driver. Skipped for jvm projects.
      if self.benchmark.language == 'jvm':
        break
      llm_fix_count += 1
      logger.log(f'Fixing {target_path} with '
                 f'{self.builder_runner.fixer_model_name}, '
                 f'attempt {llm_fix_count}.')
      self._fix_generated_fuzz_target(ai_binary, generated_oss_fuzz_project,
                                      target_path, llm_fix_count, build_result,
                                      run_result, logger)

    # Logs and returns the result.
    if not build_result.succeeded:
      logger.log(f'Failed to build {target_path} with '
                 f'{self.builder_runner.fixer_model_name} in '
                 f'{llm_fix_count} iterations of fixing.')
      return logger.return_result(
          Result(False, False, 0.0, 0.0, '', '', False,
                 SemanticCheckResult.NOT_APPLICABLE))

    logger.log(f'Successfully built {target_path} with '
               f'{self.builder_runner.fixer_model_name} in '
               f'{llm_fix_count} iterations of fixing.')

    if not run_result:
      logger.log(f'Warning: no run result in {generated_oss_fuzz_project}.')
      return logger.return_result(
          Result(True, False, 0.0, 0.0, '', '', False,
                 SemanticCheckResult.NOT_APPLICABLE))

    if run_result.coverage_summary is None or run_result.coverage is None:
      logger.log(
          f'Warning: No cov info in run result of {generated_oss_fuzz_project}.'
      )
      return logger.return_result(
          Result(True, run_result.crashes, 0.0, 0.0, '', '',
                 not run_result.succeeded, run_result.semantic_check.type))

    if not run_result.succeeded:
      logger.log(f'Warning: Failed to fix semantic error '
                 f'{run_result.semantic_check.type}'
                 f' in {generated_oss_fuzz_project}.')
      return logger.return_result(
          Result(True, run_result.crashes, 0.0, 0.0,
                 run_result.coverage_report_path, run_result.reproducer_path,
                 True, run_result.semantic_check.type))

    # Gets line coverage (diff) details.
    coverage_summary = self._load_existing_coverage_summary()
    total_lines = _compute_total_lines_without_fuzz_targets(
        coverage_summary, generated_target_name)
    if run_result.total_pcs:
      coverage_percent = run_result.cov_pcs / run_result.total_pcs
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

    logger.log(f'Result for {generated_oss_fuzz_project}: '
               f'crashes={run_result.crashes}, coverage={coverage_percent} '
               f'({run_result.cov_pcs}/{run_result.total_pcs}), '
               f'coverage diff={coverage_diff} '
               f'({run_result.coverage.covered_lines}/{total_lines})')
    return logger.return_result(
        Result(True, run_result.crashes, coverage_percent, coverage_diff,
               run_result.coverage_report_path, run_result.reproducer_path,
               not run_result.succeeded, run_result.semantic_check.type))

  def _load_existing_coverage_summary(self) -> dict:
    """Load existing summary.json."""
    return load_existing_coverage_summary(self.benchmark.project)

  def _load_existing_textcov(self) -> textcov.Textcov:
    """Loads existing textcovs."""
    return load_existing_textcov(self.benchmark.project)
