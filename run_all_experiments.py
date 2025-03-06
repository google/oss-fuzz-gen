#!/usr/bin/env python3
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
"""Run an experiment with all function-under-tests."""

import argparse
import json
import logging
import os
import re
import sys
import time
import traceback
from datetime import timedelta
from multiprocessing import Pool, Process
from typing import Any

from google.cloud import logging as cloud_logging

import run_one_experiment
from data_prep import introspector
from experiment import benchmark as benchmarklib
from experiment import evaluator, oss_fuzz_checkout, textcov
from experiment.workdir import WorkDirs
from llm_toolkit import models, prompt_builder

logger = logging.getLogger(__name__)

# WARN: Avoid large NUM_EXP for local experiments.
# NUM_EXP controls the number of experiments in parallel, while each experiment
# will evaluate {run_one_experiment.NUM_EVA, default 3} fuzz targets in
# parallel.
NUM_EXP = int(os.getenv('LLM_NUM_EXP', '2'))

# Default LLM hyper-parameters.
MAX_TOKENS: int = run_one_experiment.MAX_TOKENS
NUM_TRIALS: int = run_one_experiment.NUM_TRIALS
RUN_TIMEOUT: int = run_one_experiment.RUN_TIMEOUT
TEMPERATURE: float = run_one_experiment.TEMPERATURE

BENCHMARK_ROOT: str = './benchmark-sets'
BENCHMARK_DIR: str = f'{BENCHMARK_ROOT}/comparison'
RESULTS_DIR: str = run_one_experiment.RESULTS_DIR
GENERATED_BENCHMARK: str = 'generated-benchmark-'
JSON_REPORT = 'report.json'
TIME_STAMP_FMT = '%Y-%m-%d %H:%M:%S'

WORK_DIR = ''

LOG_LEVELS = ['debug', 'info']
LOG_FMT = ('%(asctime)s.%(msecs)03d %(levelname)s '
           '%(module)s - %(funcName)s: %(message)s')


class Result:
  benchmark: benchmarklib.Benchmark
  result: run_one_experiment.AggregatedResult | str

  def __init__(self, benchmark, result):
    self.benchmark = benchmark
    self.result = result


def get_next_generated_benchmarks_dir() -> str:
  """Retuns the next folder to be used for generated benchmarks."""
  max_idx = -1
  for benchmark_folder in os.listdir(BENCHMARK_ROOT):
    try:
      max_idx = max(max_idx,
                    int(benchmark_folder.replace(GENERATED_BENCHMARK, '')))
    except (ValueError, TypeError) as _:
      pass
  max_idx += 1
  return os.path.join(BENCHMARK_ROOT, f'{GENERATED_BENCHMARK}{max_idx}')


def generate_benchmarks(args: argparse.Namespace) -> None:
  """Generates benchmarks, write to filesystem and set args benchmark dir."""
  logger.info('Generating benchmarks.')
  benchmark_dir = get_next_generated_benchmarks_dir()
  logger.info('Setting benchmark directory to %s.', benchmark_dir)
  os.makedirs(benchmark_dir)
  args.benchmarks_directory = benchmark_dir
  benchmark_oracles = [
      heuristic.strip() for heuristic in args.generate_benchmarks.split(',')
  ]
  projects_to_target = [
      project.strip()
      for project in args.generate_benchmarks_projects.split(',')
  ]
  for project in projects_to_target:
    project_lang = oss_fuzz_checkout.get_project_language(project)
    benchmarks = introspector.populate_benchmarks_using_introspector(
        project, project_lang, args.generate_benchmarks_max, benchmark_oracles)
    if benchmarks:
      benchmarklib.Benchmark.to_yaml(benchmarks, outdir=benchmark_dir)


def prepare_experiment_targets(
    args: argparse.Namespace) -> list[benchmarklib.Benchmark]:
  """Constructs a list of experiment configs based on the |BENCHMARK_DIR| and
    |args| setting."""
  benchmark_yamls = []
  if args.benchmark_yaml:
    logger.info(
        'A benchmark yaml file %s is provided. Will use it and ignore '
        'the files in %s.', args.benchmark_yaml, args.benchmarks_directory)
    benchmark_yamls = [args.benchmark_yaml]
  else:
    if args.generate_benchmarks:
      generate_benchmarks(args)

    benchmark_yamls = [
        os.path.join(args.benchmarks_directory, file)
        for file in os.listdir(args.benchmarks_directory)
        if file.endswith('.yaml') or file.endswith('yml')
    ]
  experiment_configs = []
  for benchmark_file in benchmark_yamls:
    experiment_configs.extend(benchmarklib.Benchmark.from_yaml(benchmark_file))

  return experiment_configs


def run_experiments(benchmark: benchmarklib.Benchmark, args) -> Result:
  """Runs an experiment based on the |benchmark| config."""
  try:
    work_dirs = WorkDirs(os.path.join(args.work_dir, f'output-{benchmark.id}'))
    args.work_dirs = work_dirs
    model = models.LLM.setup(
        ai_binary=args.ai_binary,
        name=args.model,
        max_tokens=MAX_TOKENS,
        num_samples=args.num_trials,
        temperature=args.temperature,
        temperature_list=args.temperature_list,
    )

    result = run_one_experiment.run(benchmark=benchmark,
                                    model=model,
                                    args=args,
                                    work_dirs=work_dirs)
    return Result(benchmark, result)
  except Exception as e:
    logger.error('Exception while running experiment: %s', str(e))
    traceback.print_exc()
    return Result(benchmark, f'Exception while running experiment: {e}')


def parse_args() -> argparse.Namespace:
  """Parses command line arguments."""
  parser = argparse.ArgumentParser(
      description='Run all experiments that evaluates all target functions.')
  parser.add_argument('-n',
                      '--num-trials',
                      type=int,
                      default=NUM_TRIALS,
                      help='The number of trials to request from LLM.')
  parser.add_argument(
      '-t',
      '--temperature',
      type=float,
      default=TEMPERATURE,
      help=('A value between 0 and 1 representing the variety of the targets '
            'generated by LLM.'))
  parser.add_argument(
      '-tr',
      '--temperature-list',
      nargs='*',
      type=float,
      default=[],
      help=('A list of values representing the temperatures will be used by '
            'each trial LLM query.'))
  parser.add_argument('-c',
                      '--cloud-experiment-name',
                      type=str,
                      default='',
                      help='The name of the cloud experiment.')
  parser.add_argument('-cb',
                      '--cloud-experiment-bucket',
                      type=str,
                      default='',
                      help='A gcloud bucket to store experiment files.')
  parser.add_argument('-b', '--benchmarks-directory', type=str)
  parser.add_argument('-y',
                      '--benchmark-yaml',
                      type=str,
                      help='A benchmark YAML file.')
  parser.add_argument('-to', '--run-timeout', type=int, default=RUN_TIMEOUT)
  parser.add_argument('-a',
                      '--ai-binary',
                      required=False,
                      nargs='?',
                      const=os.getenv('AI_BINARY', ''),
                      default='',
                      type=str)
  parser.add_argument('-l',
                      '--model',
                      default=models.DefaultModel.name,
                      help=('Models available: '
                            f'{", ".join(models.LLM.all_llm_names())}.'))
  parser.add_argument('-td',
                      '--template-directory',
                      type=str,
                      default=prompt_builder.DEFAULT_TEMPLATE_DIR)
  parser.add_argument('-w', '--work-dir', default=RESULTS_DIR)
  parser.add_argument('--context',
                      action='store_true',
                      default=False,
                      help='Add context to function under test.')
  parser.add_argument('-e',
                      '--introspector-endpoint',
                      type=str,
                      default=introspector.DEFAULT_INTROSPECTOR_ENDPOINT)
  parser.add_argument(
      '-lo',
      '--log-level',
      help=
      f'Sets the logging level. Options available: {", ".join(LOG_LEVELS)}.',
      default='info')
  parser.add_argument(
      '-of',
      '--oss-fuzz-dir',
      help='OSS-Fuzz dir path to use. Create temporary directory by default.',
      default='')
  parser.add_argument(
      '-g',
      '--generate-benchmarks',
      help=('Generate benchmarks and use those for analysis. This is a string '
            'of comma-separated heuristics to use when identifying benchmark '
            'targets. Options available: '
            f'{", ".join(introspector.get_oracle_dict().keys())}.'),
      type=str)
  parser.add_argument(
      '-gp',
      '--generate-benchmarks-projects',
      help='Projects to generate benchmarks for in a comma separated string.',
      type=str)
  parser.add_argument('-gm',
                      '--generate-benchmarks-max',
                      help='Max targets to generate per benchmark heuristic.',
                      type=int,
                      default=5)
  parser.add_argument(
      '--delay',
      type=int,
      default=0,
      help=('Delay each experiment by certain seconds (e.g., 10s) to avoid '
            'exceeding quota limit in large scale experiments.'))
  parser.add_argument('-p',
                      '--prompt-builder',
                      help='The prompt builder to use for harness generation.',
                      default='DEFAULT')
  parser.add_argument('-ag',
                      '--agent',
                      action='store_true',
                      default=False,
                      help='Enables agent enhancement.')
  parser.add_argument('-mr',
                      '--agent-max-round',
                      type=int,
                      default=10,
                      help='Max trial round for agents.')

  args = parser.parse_args()
  if args.num_trials:
    assert args.num_trials > 0, '--num-trials must take a positive integer.'

  if args.temperature:
    assert 2 >= args.temperature >= 0, '--temperature must be within 0 and 2.'

  benchmark_yaml = args.benchmark_yaml
  if benchmark_yaml:
    assert (benchmark_yaml.endswith('.yaml') or
            benchmark_yaml.endswith('yml')), (
                "--benchmark-yaml needs to take an YAML file.")

  bench_yml = bool(benchmark_yaml)
  bench_dir = bool(args.benchmarks_directory)
  bench_gen = bool(args.generate_benchmarks)
  num_options = int(bench_yml) + int(bench_dir) + int(bench_gen)
  assert num_options == 1, (
      'One and only one of --benchmark-yaml, --benchmarks-directory and '
      '--generate-benchmarks. --benchmark-yaml takes one benchmark YAML file, '
      '--benchmarks-directory takes: a directory of them and '
      '--generate-benchmarks generates them during analysis.')

  # Validate templates.
  assert os.path.isdir(args.template_directory), (
      '--template-directory must be an existing directory.')

  # Validate cloud experiment configs.
  assert (
      bool(args.cloud_experiment_name) == bool(args.cloud_experiment_bucket)
  ), ('Cannot accept exactly one of --args.cloud-experiment-name and '
      '--args.cloud-experiment-bucket: Local experiment requires neither of '
      'them, cloud experiment needs both.')
  return args


def extend_report_with_coverage_gains() -> None:
  """Process total gain from all generated harnesses for each projects and
  update summary report. This makes it possible to view per-project stats
  as experiments complete rather than only after all experiments run."""
  coverage_gain_dict = _process_total_coverage_gain()
  existing_oss_fuzz_cov = introspector.query_introspector_language_stats()

  total_new_covgains = {}
  for project_dict in coverage_gain_dict.values():
    lang_gains = total_new_covgains.get(project_dict['language'], 0)
    lang_gains += project_dict['coverage_ofg_total_new_covered_lines']
    total_new_covgains[project_dict['language']] = lang_gains

  comparative_cov_gains = {}
  for language, lang_cov_gain in total_new_covgains.items():
    comparative_cov_gains[language] = {
        'total_coverage_increase':
            round((lang_cov_gain / existing_oss_fuzz_cov[language]['total']) *
                  100.0, 10),
        'relative_coverage_increase':
            round((lang_cov_gain / existing_oss_fuzz_cov[language]['covered']) *
                  100.0, 10)
    }
  add_to_json_report(WORK_DIR, 'coverage_gains_per_language',
                     total_new_covgains)
  add_to_json_report(WORK_DIR, 'project_summary', coverage_gain_dict)
  add_to_json_report(WORK_DIR, 'oss_fuzz_language_status',
                     existing_oss_fuzz_cov)
  add_to_json_report(WORK_DIR, 'comperative_coverage_gains',
                     comparative_cov_gains)


def extend_report_with_coverage_gains_process():
  """A process that continuously runs to update coverage gains in the
  background."""
  while True:
    time.sleep(300)  # 5 minutes.
    try:
      extend_report_with_coverage_gains()
    except Exception:
      logger.error('Failed to extend report with coverage gains')
      traceback.print_exc()


def _print_experiment_result(result: Result):
  """Prints the |result| of a single experiment."""
  logger.info('\n**** Finished benchmark %s, %s ****\n%s',
              result.benchmark.project, result.benchmark.function_signature,
              result.result)


def _print_experiment_results(results: list[Result],
                              cov_gain: dict[str, dict[str, Any]]):
  """Prints the |results| of multiple experiments."""
  logger.info('\n\n**** FINAL RESULTS: ****\n\n')
  for result in results:
    logger.info('%s\n*%s, %s*\n%s\n', '=' * 80, result.benchmark.project,
                result.benchmark.function_signature, result.result)

  logger.info('**** TOTAL COVERAGE GAIN: ****')
  for project in cov_gain:
    logger.info('*%s: %s', project, cov_gain[project]["coverage_diff"])


def _setup_logging(verbose: str = 'info', is_cloud: bool = False) -> None:
  """Set up logging level."""

  if is_cloud:
    try:
      client = cloud_logging.Client()
      client.setup_logging()
    except Exception as e:
      # For local runs we continue
      logger.warning('Error setting up cloud logging client: %s', e)

  if verbose == "debug":
    log_level = logging.DEBUG
  else:
    log_level = logging.INFO
  logging.basicConfig(
      level=log_level,
      format=LOG_FMT,
      datefmt='%Y-%m-%d %H:%M:%S',
  )
  # Set the base logger level
  logging.getLogger('').setLevel(log_level)


def add_to_json_report(outdir: str, key: str, value: Any) -> None:
  """Adds a key/value pair to JSON report."""
  os.makedirs(outdir, exist_ok=True)
  json_report_path = os.path.join(outdir, JSON_REPORT)
  if os.path.isfile(json_report_path):
    with open(json_report_path, 'r') as f:
      json_report = json.load(f)
  else:
    json_report = {}

  json_report[key] = value

  # Overwrite the new json file
  with open(json_report_path, 'w') as f:
    f.write(json.dumps(json_report))


def _process_total_coverage_gain() -> dict[str, dict[str, Any]]:
  """Processes and calculates the total coverage gain for each project."""
  textcov_dict: dict[str, list[textcov.Textcov]] = {}

  # Load all the textcov dirs
  for benchmark_dir in os.listdir(WORK_DIR):
    if not os.path.isdir(os.path.join(WORK_DIR, benchmark_dir)):
      continue

    result_benchmark_used_path = os.path.join(
        os.path.join(WORK_DIR, benchmark_dir, 'benchmark.yaml'))
    if not os.path.isfile(result_benchmark_used_path):
      continue

    project_name = ''
    ignore_patterns = []

    benchmark_used = benchmarklib.Benchmark.from_yaml(
        result_benchmark_used_path)
    if not benchmark_used:
      logger.info('Did not find benchmark for %s', benchmark_dir)
      try:
        project_name = '-'.join(benchmark_dir.split('-')[1:-1])
      except:
        continue
    else:
      logger.info('Found benchmark for %s', benchmark_dir)
      project_name = benchmark_used[0].project
      target_basename = os.path.basename(benchmark_used[0].target_path)
      ignore_patterns = [re.compile(r'^' + re.escape(target_basename) + ':')]

    coverage_reports = os.path.join(WORK_DIR, benchmark_dir,
                                    'code-coverage-reports')
    if not os.path.isdir(coverage_reports):
      continue

    if project_name not in textcov_dict:
      textcov_dict[project_name] = []
    for trial in os.listdir(coverage_reports):
      summary = os.path.join(coverage_reports, trial, 'textcov')
      if not os.path.isdir(summary):
        continue

      for textcov_file in os.listdir(summary):
        if textcov_file.endswith('.covreport'):
          with open(os.path.join(summary, textcov_file), 'rb') as f:
            if benchmark_used[0].language == 'rust':
              textcov_dict[project_name].append(textcov.Textcov.from_file(f))
            else:
              textcov_dict[project_name].append(
                  textcov.Textcov.from_rust_file(
                      f, ignore_function_patterns=ignore_patterns))
        elif textcov_file == 'all_cov.json':
          with open(os.path.join(summary, textcov_file)) as f:
            textcov_dict[project_name].append(
                textcov.Textcov.from_python_file(f))
        elif textcov_file == 'jacoco.xml':
          with open(os.path.join(summary, textcov_file)) as f:
            textcov_dict[project_name].append(textcov.Textcov.from_jvm_file(f))

  if not textcov_dict:
    return {}

  coverage_gain: dict[str, dict[str, Any]] = {}
  for project, cov_list in textcov_dict.items():
    total_cov = textcov.Textcov()
    for cov in cov_list:
      total_cov.merge(cov)
    existing_textcov = evaluator.load_existing_textcov(project)
    coverage_summary = evaluator.load_existing_coverage_summary(project)

    try:
      coverage_summary_files = coverage_summary['data'][0]['files']
      lines = [f['summary']['lines']['count'] for f in coverage_summary_files]
    except (KeyError, TypeError):
      lines = []

    total_existing_lines = sum(lines)
    total_cov_covered_lines_before_subtraction = total_cov.covered_lines
    total_cov.subtract_covered_lines(existing_textcov)
    try:
      cov_relative_gain = (total_cov.covered_lines /
                           existing_textcov.covered_lines)
    except ZeroDivisionError:
      cov_relative_gain = 0.0

    total_lines = max(total_cov.total_lines, total_existing_lines)

    if total_lines:
      coverage_gain[project] = {
          'language':
              oss_fuzz_checkout.get_project_language(project),
          'coverage_diff':
              total_cov.covered_lines / total_lines,
          'coverage_relative_gain':
              cov_relative_gain,
          'coverage_ofg_total_covered_lines':
              total_cov_covered_lines_before_subtraction,
          'coverage_ofg_total_new_covered_lines':
              total_cov.covered_lines,
          'coverage_existing_total_covered_lines':
              existing_textcov.covered_lines,
          'coverage_existing_total_lines':
              total_existing_lines,
      }
    else:
      # Fail safe when total_lines is 0 because of invalid coverage report
      logger.warning(
          'Line coverage information missing from the coverage report.')
      coverage_gain[project] = {'coverage_diff': 0.0}

  return coverage_gain


def main():
  global WORK_DIR

  args = parse_args()
  _setup_logging(args.log_level, is_cloud=args.cloud_experiment_name != '')
  logger.info('Starting experiments on PR branch')

  # Capture time at start
  start = time.time()
  add_to_json_report(args.work_dir, 'start_time',
                     time.strftime(TIME_STAMP_FMT, time.gmtime(start)))

  # Set introspector endpoint before performing any operations to ensure the
  # right API endpoint is used throughout.
  introspector.set_introspector_endpoints(args.introspector_endpoint)

  run_one_experiment.prepare(args.oss_fuzz_dir)

  experiment_targets = prepare_experiment_targets(args)
  if oss_fuzz_checkout.ENABLE_CACHING:
    oss_fuzz_checkout.prepare_cached_images(experiment_targets)

  logger.info('Running %s experiment(s) in parallels of %s.',
              len(experiment_targets), str(NUM_EXP))

  # Set global variables that are updated throughout experiment runs.
  WORK_DIR = args.work_dir

  if args.cloud_experiment_name:
    coverage_gains_process = Process(
        target=extend_report_with_coverage_gains_process)
    coverage_gains_process.start()
  else:
    coverage_gains_process = None

  experiment_results = []
  if NUM_EXP == 1:
    for target_benchmark in experiment_targets:
      result = run_experiments(target_benchmark, args)
      _print_experiment_result(result)
      experiment_results.append(result)
  else:
    experiment_tasks = []
    with Pool(NUM_EXP, maxtasksperchild=1) as p:
      for target_benchmark in experiment_targets:
        experiment_task = p.apply_async(run_experiments,
                                        (target_benchmark, args),
                                        callback=_print_experiment_result)
        experiment_tasks.append(experiment_task)
        time.sleep(args.delay)

      experiment_results = [task.get() for task in experiment_tasks]

      # Signal that no more work will be submitte to the pool.
      p.close()

      # Wait for all workers to complete.
      p.join()

  if coverage_gains_process:
    # Do a final coverage aggregation.
    coverage_gains_process.kill()
    extend_report_with_coverage_gains()

  # Capture time at end
  end = time.time()
  add_to_json_report(args.work_dir, 'completion_time',
                     time.strftime(TIME_STAMP_FMT, time.gmtime(end)))
  add_to_json_report(args.work_dir, 'total_run_time',
                     str(timedelta(seconds=end - start)))

  coverage_gain_dict = _process_total_coverage_gain()
  _print_experiment_results(experiment_results, coverage_gain_dict)


if __name__ == '__main__':
  sys.exit(main())
