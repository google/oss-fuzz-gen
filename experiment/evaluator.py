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
  finished: bool = False
  compiles: bool = False
  crashes: bool = False
  coverage: float = 0.0
  line_coverage_diff: float = 0.0
  newly_covered_lines: int = 0
  total_lines: int = 0
  baseline_total_lines: int = 0
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
    self.baseline_total_lines = 0
    try:
      # Load baseline coverage summary to get total lines.
      baseline_summary = load_existing_coverage_summary(self.benchmark.project)
      if baseline_summary:
          target_basename = os.path.basename(self.benchmark.target_path)
          self.baseline_total_lines = \
              compute_total_lines_without_fuzz_targets(
                  baseline_summary, target_basename)
      logger.info('Baseline total lines for %s: %d', self.benchmark.project,
                  self.baseline_total_lines)
    except Exception as e:
        logger.error('Failed to load baseline summary/calculate total lines: %s', e)
        # Keep baseline_total_lines as 0

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
    generated_project_path = os.path.join(oss_fuzz_checkout.OSS_FUZZ_DIR,
                                          'projects', name)
    if os.path.exists(generated_project_path):
      logger.info('Project %s already exists.', generated_project_path)
      return name

    existing_project_path = os.path.join(oss_fuzz_checkout.OSS_FUZZ_DIR,
                                         'projects', self.benchmark.project)

    shutil.copytree(existing_project_path, generated_project_path)

    # Copy generated fuzzers to generated_project_path
    shutil.copyfile(
        target_file,
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

  def _calculate_coverage_metrics(self, run_result: RunResult,
                                  existing_textcov: textcov.Textcov,
                                  generated_target_name: str,
                                  dual_logger: _Logger) -> tuple[int, int, float, float]:
    """Calculates various coverage metrics based on run result and baseline.

    Returns:
        Tuple containing: (newly_covered_lines, union_total_lines, coverage_diff, coverage_percent)
    """
    newly_covered_lines = 0
    union_total_lines = 0
    coverage_diff = 0.0
    coverage_percent = 0.0
    total_lines_for_percent = 0 # Used for overall % calculation

    current_coverage_copy = None
    if run_result and run_result.coverage:
        # Create a deep copy for calculating the union and original total lines
        current_coverage_copy = run_result.coverage.copy()

    # Calculate Union Total Lines (Denominator for diff)
    if current_coverage_copy:
        # Merge baseline into the copy of the current run's coverage
        merged_coverage = current_coverage_copy.copy() # Copy again to avoid modifying current_coverage_copy
        merged_coverage.merge(existing_textcov)
        union_total_lines = merged_coverage.total_lines
    else:
        # If no current coverage, union total is just baseline total
        union_total_lines = existing_textcov.total_lines

    # Calculate Newly Covered Lines (Numerator for diff)
    if run_result and run_result.coverage:
        # Subtract baseline coverage from the original run_result coverage object
        # This modifies run_result.coverage in place to hold the diff
        run_result.coverage.subtract_covered_lines(existing_textcov)
        newly_covered_lines = run_result.coverage.covered_lines

    # Calculate Coverage Diff using the union total lines
    if union_total_lines > 0:
        coverage_diff = newly_covered_lines / union_total_lines
    else:
        if newly_covered_lines > 0:
            dual_logger.log(
                f'Warning: union_total_lines is 0 but newly_covered_lines is {newly_covered_lines}. Cannot calculate coverage diff accurately.'
            )
        # Keep coverage_diff as 0.0 if denominator is 0
        coverage_diff = 0.0

    # --- Calculate overall coverage percentage --- #
    if run_result:
        if run_result.total_pcs > 0: # Prefer pcs-based coverage if available
            coverage_percent = run_result.cov_pcs / run_result.total_pcs
        else:
            # Fallback to line-based percentage calculation using original coverage
            original_covered_lines = 0
            if current_coverage_copy: # Use the original coverage before subtraction
                total_lines_for_percent = current_coverage_copy.total_lines
                original_covered_lines = current_coverage_copy.covered_lines

            # If still 0 total lines, try loading from summary (less preferred)
            # This might happen if the Textcov object couldn't be generated correctly
            if total_lines_for_percent == 0:
                coverage_summary = self._load_existing_coverage_summary()
                if coverage_summary:
                    total_lines_for_percent = compute_total_lines_without_fuzz_targets(
                        coverage_summary, generated_target_name)
                    # Cannot easily get original_covered_lines from summary
                    original_covered_lines = -1 # Indicate unable to calculate line % this way

            if total_lines_for_percent > 0 and original_covered_lines != -1:
                 coverage_percent = original_covered_lines / total_lines_for_percent
            else:
                # Only log warning if we couldn't calculate percentage either way
                if run_result.total_pcs <= 0:
                    dual_logger.log(
                        f'Warning: Could not determine coverage percentage in {generated_oss_fuzz_project}. total_pcs={run_result.total_pcs}, total_lines={total_lines_for_percent}')
                coverage_percent = 0.0

    return newly_covered_lines, union_total_lines, coverage_diff, coverage_percent

  def check_target(self, ai_binary, target_path: str) -> Result:
    generated_target_name = os.path.basename(target_path)
    sample_id = os.path.splitext(generated_target_name)[0]
    generated_oss_fuzz_project = f'{self.benchmark.id}-{sample_id}'
    generated_oss_fuzz_project = rectify_docker_tag(generated_oss_fuzz_project)
    self.create_ossfuzz_project(generated_oss_fuzz_project, target_path)

    status_path = os.path.join(self.work_dirs.status, sample_id)
    os.makedirs(status_path, exist_ok=True)
    dual_logger = _Logger(status_path)

    if GENERATE_CORPUS:
        self.extend_build_with_corpus(ai_binary, target_path,
                                    generated_oss_fuzz_project)

    llm_fix_count = 0
    build_result = None
    run_result = None

    # Loop of evaluating and fixing fuzz target.
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
            run_result = None # Ensure run_result is None on exception

        # 2. Calculate coverage metrics
        newly_covered_lines = 0
        union_total_lines = 0
        coverage_diff = 0.0
        coverage_percent = 0.0
        if run_result: # Only calculate if run_result exists
            # Load baseline coverage needed for calculation
            # TODO(dongge): Move load_existing_textcov to OSS-Fuzz module so that we only
            # need to run it once.
            existing_textcov = self.load_existing_textcov()

            (newly_covered_lines, union_total_lines,
             coverage_diff, coverage_percent) = self._calculate_coverage_metrics(
                                                             run_result,
                                                             existing_textcov,
                                                             generated_target_name,
                                                             dual_logger)
            # Note: run_result.coverage is modified in place by _calculate_coverage_metrics
            # to contain the textcov diff.

        # Determine success based on build status and coverage diff
        gen_succ = False
        # Ensure build_result exists before checking build_result.succeeded
        current_build_succeeded = build_result.succeeded if build_result else False
        if current_build_succeeded and run_result: # Check run_result exists too
            if self.benchmark.language == 'jvm':
                # JVM success requires build, run, AND positive diff (if run didn't crash)
                gen_succ = True # Start assuming success if build is ok
                if run_result.succeeded:
                    gen_succ = (coverage_diff > 0)
            else:
                # Other languages just need build success for generation success
                gen_succ = True
        elif current_build_succeeded and not run_result:
             # If build succeeded but run failed (e.g. exception before runner)
             # consider it not successful for breaking the loop, needs fix.
             gen_succ = False

        if gen_succ or llm_fix_count >= LLM_FIX_LIMIT:
            break # Exit loop on success or fix limit

        # 3. Fixing generated driver (Only run if not gen_succ and limit not reached)
        llm_fix_count += 1
        dual_logger.log(f'Fixing {target_path} with '
                        f'{self.builder_runner.fixer_model_name}, '
                        f'attempt {llm_fix_count}.')
        try:
             # Ensure build_result is passed even if previous run failed
             current_build_result = build_result if build_result else BuildResult()
             self._fix_generated_fuzz_target(ai_binary, generated_oss_fuzz_project,
                                             target_path, llm_fix_count,
                                             current_build_result, run_result, dual_logger,
                                             self.benchmark.language)
        except Exception as e:
            dual_logger.log('Exception occurred when fixing fuzz target in attempt '
                            f'{llm_fix_count}: {e}')
            # Decide if we should break here or continue? Breaking seems safer.
            break

    # --- Post-Loop: Logs and returns the result --- #
    final_build_succeeded = build_result.succeeded if build_result else False
    final_compile_log = build_result.log_path if build_result else ''

    # Gather final run results safely
    final_run_crashes = False
    final_run_succeeded = False
    final_semantic_type = SemanticCheckResult.NOT_APPLICABLE
    final_triage = TriageResult.NOT_APPLICABLE
    final_report_path = ''
    final_reproducer_path = ''
    final_textcov_diff = textcov.Textcov() # Default to empty

    if run_result:
        final_run_crashes = run_result.crashes
        final_run_succeeded = run_result.succeeded
        final_semantic_type = run_result.semantic_check.type
        # Triage might happen inside the loop or after, check run_result.triage
        final_triage = run_result.triage
        final_report_path = run_result.coverage_report_path
        final_reproducer_path = run_result.reproducer_path
        # run_result.coverage now holds the diff textcov after _calculate_coverage_metrics
        if run_result.coverage:
            final_textcov_diff = run_result.coverage

        # Triage if crash occurred and triage hasn't happened yet
        if final_run_crashes and final_triage == TriageResult.NOT_APPLICABLE:
            dual_logger.log(f'Triaging the crash related to {target_path} ...')
            final_triage = self.triage_crash(
                 ai_binary,
                 generated_oss_fuzz_project,
                 target_path,
                 run_result, # Pass the original run_result for triage
                 dual_logger,
            )

    # --- Final Result Reporting --- #
    if not final_build_succeeded:
        dual_logger.log(f'Failed to build {target_path} after {llm_fix_count} fix attempts.')
        result = Result(finished=True, # Mark as finished
                        compiles=False,
                        crashes=False, coverage=0.0, line_coverage_diff=0.0,
                        newly_covered_lines=0, total_lines=0, baseline_total_lines=self.baseline_total_lines,
                        coverage_report_path='', reproducer_path='', is_semantic_error=False,
                        semantic_error=SemanticCheckResult.NOT_APPLICABLE,
                        triage=TriageResult.NOT_APPLICABLE, textcov_diff=textcov.Textcov(),
                        compile_error=final_compile_log, compile_log=final_compile_log)
    else:
        dual_logger.log(f'Finished check for {target_path}. Build successful. Fix attempts: {llm_fix_count}.')
        dual_logger.log(
             f'Final Stats: '
             f'crashes={final_run_crashes}, coverage={coverage_percent:.4f}, '
             f'newly covered lines={newly_covered_lines}, union total lines={union_total_lines}, baseline total lines={self.baseline_total_lines}, '
             f'coverage diff={coverage_diff:.4f}'
        )
        result = Result(finished=True, # Mark as finished
                        compiles=True,
                        crashes=final_run_crashes,
                        coverage=coverage_percent,
                        line_coverage_diff=coverage_diff,
                        newly_covered_lines=newly_covered_lines,
                        total_lines=union_total_lines,
                        baseline_total_lines=self.baseline_total_lines,
                        coverage_report_path=final_report_path,
                        reproducer_path=final_reproducer_path,
                        is_semantic_error=(not final_run_succeeded),
                        semantic_error=final_semantic_type,
                        triage=final_triage,
                        textcov_diff=final_textcov_diff,
                        compile_error=final_compile_log,
                        compile_log=final_compile_log)

    return dual_logger.return_result(result)

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
