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
import logging
import os
import re
import shutil
from typing import Optional

from google.cloud import storage

from experiment import builder_runner, oss_fuzz_checkout, textcov
from experiment.benchmark import Benchmark
from experiment.builder_runner import BuildResult, RunResult
from experiment.fuzz_target_error import SemanticCheckResult
from experiment.workdir import WorkDirs
from llm_toolkit import code_fixer, corpus_generator, crash_triager
from llm_toolkit.crash_triager import TriageResult

logger = logging.getLogger(__name__)

LLM_FIX_LIMIT = int(os.getenv('LLM_FIX_LIMIT', '5'))
GENERATE_CORPUS = bool(os.getenv('LLM_GENERATE_CORPUS', ''))

OSS_FUZZ_COVERAGE_BUCKET = 'oss-fuzz-coverage'
OSS_FUZZ_INTROSPECTOR_BUCKET = 'oss-fuzz-introspector'


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
  triage: str = ''
  textcov_diff: textcov.Textcov = dataclasses.field(
      default_factory=textcov.Textcov)
  # Deprecated renamed fields. Keeping them for backward compatibility.
  # TODO https://github.com/google/oss-fuzz-gen/issues/215
  is_driver_fuzz_err: bool = dataclasses.field(kw_only=True, default=False)
  driver_fuzz_err: str = dataclasses.field(kw_only=True, default='')
  compile_error: str = ''
  compile_log: str = ''

  def __post_init__(self, *args, **kwargs):  # pylint: disable=unused-argument
    if self.is_driver_fuzz_err:
      self.is_semantic_error = self.is_driver_fuzz_err
    if self.driver_fuzz_err:
      self.semantic_error = self.driver_fuzz_err

  def to_dict(self):
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
    logger.info('No existing coverage report. Using empty.')
    return textcov.Textcov()

  # Find the latest generated textcov date.
  latest_dir = sorted(blobs.prefixes)[-1]  # type: ignore
  blobs = storage_client.list_blobs(bucket, prefix=latest_dir)

  # Download and merge them.
  existing_textcov = textcov.Textcov()
  for blob in blobs:
    if not blob.name.endswith('.covreport'):
      continue

    logger.info('Loading existing textcov from %s', blob.name)
    with blob.open('rb') as f:
      existing_textcov.merge(textcov.Textcov.from_file(f))

  return existing_textcov


def load_existing_jvm_textcov(project: str) -> textcov.Textcov:
  """Loads existing textcovs for JVM project."""
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
    logger.info('No existing coverage report. Using empty.')
    return textcov.Textcov()

  latest_dir = sorted(blobs.prefixes)[-1]  # type: ignore
  blob = bucket.blob(f'{latest_dir}linux/jacoco.xml')
  logger.info('Loading existing jacoco.xml textcov from %s', blob.name)
  with blob.open() as f:
    return textcov.Textcov.from_jvm_file(f)


def load_existing_python_textcov(project: str) -> textcov.Textcov:
  """Loads existing textcovs for python project."""
  storage_client = storage.Client.create_anonymous_client()
  bucket = storage_client.bucket(OSS_FUZZ_INTROSPECTOR_BUCKET)
  blobs = storage_client.list_blobs(bucket,
                                    prefix=f'{project}/inspector-report/',
                                    delimiter='/')
  # Iterate through all blobs first to get the prefixes (i.e. "subdirectories").
  for blob in blobs:
    continue

  if not blobs.prefixes:  # type: ignore
    # No existing coverage reports.
    logger.info('No existing coverage report. Using empty.')
    return textcov.Textcov()

  latest_dir = sorted(blobs.prefixes)[-1]  # type: ignore
  blob = bucket.blob(f'{latest_dir}all_cov.json')
  logger.info('Loading existing all_cov.json textcov from %s', blob.name)
  with blob.open() as f:
    return textcov.Textcov.from_python_file(f)


def load_existing_rust_textcov(project: str) -> textcov.Textcov:
  """Loads existing textcovs for rust project."""
  storage_client = storage.Client.create_anonymous_client()
  bucket = storage_client.bucket(OSS_FUZZ_INTROSPECTOR_BUCKET)
  blobs = storage_client.list_blobs(bucket,
                                    prefix=f'{project}/inspector-report/',
                                    delimiter='/')
  # Iterate through all blobs first to get the prefixes (i.e. "subdirectories").
  for blob in blobs:
    continue

  if not blobs.prefixes:  # type: ignore
    # No existing coverage reports.
    logger.info('No existing coverage report. Using empty.')
    return textcov.Textcov()

  # Find the latest generated textcov date.
  latest_dir = sorted(blobs.prefixes)[-1]  # type: ignore
  blobs = storage_client.list_blobs(bucket, prefix=latest_dir)

  # Download and merge them.
  existing_textcov = textcov.Textcov()
  for blob in blobs:
    if not blob.name.endswith('.covreport'):
      continue

    logger.info('Loading existing textcov from %s', blob.name)
    with blob.open('rb') as f:
      existing_textcov.merge(textcov.Textcov.from_rust_file(f))

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
    logger.info('No existing coverage reports, using empty one.')
    return {}

  latest_dir = sorted(blobs.prefixes)[-1]  # type: ignore
  blob = bucket.blob(f'{latest_dir}linux/summary.json')
  logger.info('Loading existing summary.json from %s', blob.name)
  with blob.open() as f:
    return json.load(f)


def compute_total_lines_without_fuzz_targets(coverage_summary: dict,
                                             fuzz_target_base_name: str) -> int:
  """Counts the total number of lines excluding the fuzz target."""
  # TODO(dongge): Exclude all fuzz targets if there are multiple.
  return sum([
      f['summary']['lines']['count']
      for f in coverage_summary['data'][0]['files']
      if fuzz_target_base_name not in f['filename']
  ])


def rectify_docker_tag(docker_tag: str) -> str:
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
    logger.info(*args, *kwargs)
    print(*args, *kwargs, file=self._log)
    self._log.flush()

  def return_result(self, result: Result):
    with open(self._result_path, 'w') as f:
      json.dump(result.to_dict(), f)

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

  def create_ossfuzz_project(self,
                             name: str,
                             target_file: str,
                             build_script_path: str = '') -> str:
    """Creates an OSS-Fuzz project with the generated target. The new project
    will replicate an existing project |name| but replace its fuzz target
    and build script with the new |target_file| and |build_script_path|."""
    logger.info('target file: %s', target_file)
    logger.info('Execution create_ossfuzz_project name: %s', name)
    logger.info('Execution create_ossfuzz_project buid_script_path: %s',
                build_script_path)
    generated_project_path = os.path.join(oss_fuzz_checkout.OSS_FUZZ_DIR,
                                          'projects', name)
    logger.info('Execution create_ossfuzz_project generated_project_path: %s', \
                generated_project_path)
    if os.path.exists(generated_project_path):
      logger.info('Project %s already exists.', generated_project_path)
      return name

    existing_project_path = os.path.join(oss_fuzz_checkout.OSS_FUZZ_DIR,
                                         'projects', self.benchmark.project)
    logger.info('Execution create_ossfuzz_project existing_project_path: %s', \
                existing_project_path)

    shutil.copytree(existing_project_path, generated_project_path)

    # Copy generated fuzzers to generated_project_path
    shutil.copyfile(
        target_file,
        os.path.join(generated_project_path, os.path.basename(target_file)))
    logger.info('Execution dst os.path.join(generated_project_path, os.path.basename(target_file)): %s', \
                os.path.join(generated_project_path, os.path.basename(target_file)))

    # Add additional statement in dockerfile to overwrite with generated fuzzer
    with open(os.path.join(generated_project_path, 'Dockerfile'), 'a') as f:
      f.write(f'\nCOPY {os.path.basename(target_file)} '
              f'{self.benchmark.target_path}\n')

    if not build_script_path or os.path.getsize(build_script_path) == 0:
      return name

    # Copy generated build script to generated_project_path
    shutil.copyfile(
        build_script_path,
        os.path.join(generated_project_path,
                     os.path.basename('agent-build.sh')))

    # Add additional statement in dockerfile to overwrite with generated fuzzer
    with open(os.path.join(generated_project_path, 'Dockerfile'), 'a') as f:
      f.write('\nRUN cp /src/build.sh /src/build.bk.sh\n')
    with open(os.path.join(generated_project_path, 'Dockerfile'), 'a') as f:
      f.write('\nCOPY agent-build.sh /src/build.sh\n')

    return name

  def _fix_generated_fuzz_target(self, ai_binary: str,
                                 generated_oss_fuzz_project: str,
                                 target_path: str, iteration: int,
                                 build_result: BuildResult,
                                 run_result: Optional[RunResult],
                                 dual_logger: _Logger, language: str):
    """Fixes the generated fuzz target."""
    error_desc, errors = '', []
    if build_result.succeeded:
      if language != 'jvm':
        if run_result:
          error_desc, errors = run_result.semantic_check.get_error_info()
        else:
          dual_logger.log(f'Warning: Build succeed but no run_result in '
                          f'{generated_oss_fuzz_project}.')
    else:
      error_desc, errors = None, build_result.errors

    code_fixer.llm_fix(ai_binary, target_path, self.benchmark, iteration,
                       error_desc, errors, self.builder_runner.fixer_model_name,
                       language)
    shutil.copyfile(
        target_path,
        os.path.join(oss_fuzz_checkout.OSS_FUZZ_DIR, 'projects',
                     generated_oss_fuzz_project, os.path.basename(target_path)))

  def triage_crash(
      self,
      ai_binary: str,
      generated_oss_fuzz_project: str,
      driver_path: str,
      run_result: RunResult,
      dual_logger: _Logger,
  ) -> str:
    """Triages the crash."""
    if run_result.crash_info:
      crash_info = run_result.crash_info
      crash_func = run_result.semantic_check.crash_func
      return crash_triager.llm_triage(
          ai_binary,
          driver_path,
          self.benchmark,
          crash_info,
          crash_func,
          self.builder_runner.fixer_model_name,
      )

    dual_logger.log(f'Warning: no crash info in {generated_oss_fuzz_project}.')
    return TriageResult.NOT_APPLICABLE

  def extend_build_with_corpus(self, ai_binary, target_path,
                               generated_oss_fuzz_project):
    """Extends an OSS-Fuzz project with corpus generated programmatically."""
    generated_project_path = os.path.join(oss_fuzz_checkout.OSS_FUZZ_DIR,
                                          'projects',
                                          generated_oss_fuzz_project)
    generated_corp = corpus_generator.get_script(
        ai_binary, self.builder_runner.fixer_model_name, target_path,
        self.benchmark)

    corpus_generator_path = os.path.join(generated_project_path, 'corp_gen.py')
    with open(corpus_generator_path, 'w') as f:
      f.write(generated_corp)

    with open(os.path.join(generated_project_path, 'Dockerfile'), 'a') as f:
      f.write('COPY corp_gen.py $SRC/corp_gen.py\n')
    target_harness_file = os.path.basename(self.benchmark.target_path)
    target_harness_file = os.path.splitext(target_harness_file)[0]
    corpus_dst = '/src/generated-corpus/*'
    with open(os.path.join(generated_project_path, 'build.sh'), 'a') as f:
      f.write('\n# Generate a corpus for the modified harness.')
      f.write('\nmkdir -p /src/generated-corpus')
      f.write('\npushd /src/generated-corpus')
      f.write('\npython3 $SRC/corp_gen.py')
      f.write('\npopd')
      f.write(f'\nzip $OUT/{target_harness_file}_seed_corpus.zip {corpus_dst}')

  def check_target(self, ai_binary, target_path: str) -> Result:
    """Builds and runs a target."""
    generated_target_name = os.path.basename(target_path)
    sample_id = os.path.splitext(generated_target_name)[0]
    generated_oss_fuzz_project = f'{self.benchmark.id}-{sample_id}'
    generated_oss_fuzz_project = rectify_docker_tag(generated_oss_fuzz_project)
    self.create_ossfuzz_project(generated_oss_fuzz_project, target_path)

    status_path = os.path.join(self.work_dirs.status, sample_id)
    os.makedirs(status_path, exist_ok=True)

    dual_logger = _Logger(status_path)

    # Try building and running the new target.

    # TODO: Log build failure.
    # TODO: Log run success/failure.

    if GENERATE_CORPUS:
      self.extend_build_with_corpus(ai_binary, target_path,
                                    generated_oss_fuzz_project)

    # Loop of evaluating and fixing fuzz target.
    llm_fix_count = 0
    while True:
      # 1. Evaluating generated driver.
      try:
        build_result, run_result = self.builder_runner.build_and_run(
            generated_oss_fuzz_project, target_path, llm_fix_count,
            self.benchmark.language)
      except Exception as e:
        dual_logger.log(
            'Exception occurred when building and running fuzz target '
            f'in attempt {llm_fix_count}: {e}')
        build_result = BuildResult()
        run_result = None

      # 2. Calculate coverage percentage and coverage diff
      coverage_summary = None
      total_lines = 0
      coverage_percent = 0.0
      coverage_diff = 0.0
      if run_result:
        # Gets line coverage (diff) details.
        coverage_summary = self._load_existing_coverage_summary()

        if self.benchmark.language in ['python', 'jvm'] and run_result.coverage:
          # The Jacoco.xml coverage report used to generate summary.json on
          # OSS-Fuzz for JVM projects does not trace the source file location.
          # Thus the conversion may miss some classes because they are not
          # present during coverage report generation. This fix gets the total
          # line calculation from the jacoco.xml report of the current run
          # directly and compares it with the total_lines retrieved from
          # summary.json. Then the larger total_lines is used which is assumed
          # to be more accurate. This is the same case for python project which
          # the total line is determined from the all_cov.json file.
          total_lines = run_result.coverage.total_lines
        elif coverage_summary:
          total_lines = compute_total_lines_without_fuzz_targets(
              coverage_summary, generated_target_name)
        else:
          total_lines = 0

        if run_result.total_pcs:
          coverage_percent = run_result.cov_pcs / run_result.total_pcs
        else:
          dual_logger.log(
              f'Warning: total_pcs == 0 in {generated_oss_fuzz_project}.')
          coverage_percent = 0.0

        existing_textcov = self.load_existing_textcov()
        if run_result.coverage:
          run_result.coverage.subtract_covered_lines(existing_textcov)

        if total_lines and run_result.coverage:
          coverage_diff = run_result.coverage.covered_lines / total_lines
        else:
          dual_logger.log(
              f'Warning: total_lines == 0 in {generated_oss_fuzz_project}.')
          coverage_diff = 0.0

      if self.benchmark.language == 'jvm':
        # For JVM, the generation is consider success if either is true
        # 1) Build success and run crashed (expected for exceptions)
        # 2) Build success, run success and coverage diff > 0
        gen_succ = build_result.succeeded and run_result
        if gen_succ and run_result and run_result.succeeded:
          gen_succ = gen_succ and (coverage_diff > 0)
      else:
        # Should not concern run_result.succeeded for generation otherwise
        # it may make a good fuzz target bad.
        # Should concern run_result.succeeded for analyzes to know semantic
        # errors
        gen_succ = build_result.succeeded

      if gen_succ or llm_fix_count >= LLM_FIX_LIMIT:
        # Exit cond 1: successfully generate the fuzz target.
        # Exit cond 2: fix limit is reached.
        break

      # 2. Fixing generated driver
      llm_fix_count += 1
      dual_logger.log(f'Fixing {target_path} with '
                      f'{self.builder_runner.fixer_model_name}, '
                      f'attempt {llm_fix_count}.')
      try:
        self._fix_generated_fuzz_target(ai_binary, generated_oss_fuzz_project,
                                        target_path, llm_fix_count,
                                        build_result, run_result, dual_logger,
                                        self.benchmark.language)
      except Exception as e:
        dual_logger.log('Exception occurred when fixing fuzz target in attempt '
                        f'{llm_fix_count}: {e}')
        break

    # Logs and returns the result.
    if not build_result.succeeded:
      dual_logger.log(f'Failed to build {target_path} with '
                      f'{self.builder_runner.fixer_model_name} in '
                      f'{llm_fix_count} iterations of fixing.')
      return dual_logger.return_result(
          Result(False,
                 False,
                 0.0,
                 0.0,
                 '',
                 '',
                 False,
                 SemanticCheckResult.NOT_APPLICABLE,
                 TriageResult.NOT_APPLICABLE,
                 compile_error=build_result.log_path,
                 compile_log=build_result.log_path))

    dual_logger.log(f'Successfully built {target_path} with '
                    f'{self.builder_runner.fixer_model_name} in '
                    f'{llm_fix_count} iterations of fixing.')

    if not run_result:
      dual_logger.log(
          f'Warning: no run result in {generated_oss_fuzz_project}.')
      return dual_logger.return_result(
          Result(True,
                 False,
                 0.0,
                 0.0,
                 '',
                 '',
                 False,
                 SemanticCheckResult.NOT_APPLICABLE,
                 TriageResult.NOT_APPLICABLE,
                 compile_error=build_result.log_path,
                 compile_log=build_result.log_path))

    # Triage the crash with LLM
    dual_logger.log(f'Triaging the crash related to {target_path} with '
                    f'{self.builder_runner.fixer_model_name}.')
    run_result.triage = self.triage_crash(
        ai_binary,
        generated_oss_fuzz_project,
        target_path,
        run_result,
        dual_logger,
    )

    if run_result.coverage_summary is None or run_result.coverage is None:
      dual_logger.log(
          f'Warning: No cov info in run result of {generated_oss_fuzz_project}.'
      )
      return dual_logger.return_result(
          Result(True,
                 run_result.crashes,
                 0.0,
                 0.0,
                 '',
                 '',
                 not run_result.succeeded,
                 run_result.semantic_check.type,
                 run_result.triage,
                 compile_error=build_result.log_path,
                 compile_log=build_result.log_path))

    dual_logger.log(
        f'Result for {generated_oss_fuzz_project}: '
        f'crashes={run_result.crashes}, coverage={coverage_percent} '
        f'({run_result.cov_pcs}/{run_result.total_pcs}), '
        f'coverage diff={coverage_diff} '
        f'({run_result.coverage.covered_lines}/{total_lines})')
    return dual_logger.return_result(
        Result(True,
               run_result.crashes,
               coverage_percent,
               coverage_diff,
               run_result.coverage_report_path,
               run_result.reproducer_path,
               not run_result.succeeded,
               run_result.semantic_check.type,
               run_result.triage,
               run_result.coverage,
               compile_error=build_result.log_path,
               compile_log=build_result.log_path))

  def _load_existing_coverage_summary(self) -> dict:
    """Load existing summary.json."""
    return load_existing_coverage_summary(self.benchmark.project)

  def load_existing_textcov(self) -> textcov.Textcov:
    """Loads existing textcovs."""
    if self.benchmark.language == 'jvm':
      return load_existing_jvm_textcov(self.benchmark.project)

    if self.benchmark.language == 'python':
      return load_existing_python_textcov(self.benchmark.project)

    if self.benchmark.language == 'rust':
      return load_existing_rust_textcov(self.benchmark.project)

    return load_existing_textcov(self.benchmark.project)
