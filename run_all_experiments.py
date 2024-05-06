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
import logging
import os
import sys
import time
import traceback
from multiprocessing import Pool

import run_one_experiment
from data_prep import introspector
from experiment import benchmark as benchmarklib
from experiment.workdir import WorkDirs
from llm_toolkit import models, prompt_builder

# WARN: Avoid large NUM_EXP for local experiments.
# NUM_EXP controls the number of experiments in parallel, while each experiment
# will evaluate {run_one_experiment.NUM_EVA, default 3} fuzz targets in
# parallel.
NUM_EXP = int(os.getenv('LLM_NUM_EXP', '2'))

# Default LLM hyper-parameters.
MAX_TOKENS: int = run_one_experiment.MAX_TOKENS
NUM_SAMPLES: int = run_one_experiment.NUM_SAMPLES
RUN_TIMEOUT: int = run_one_experiment.RUN_TIMEOUT
TEMPERATURE: float = run_one_experiment.TEMPERATURE

BENCHMARK_ROOT: str = './benchmark-sets'
BENCHMARK_DIR: str = f'{BENCHMARK_ROOT}/comparison'
RESULTS_DIR: str = run_one_experiment.RESULTS_DIR
GENERATED_BENCHMARK: str = 'generated-benchmark-'


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
  logging.info('Generating benchmarks.')
  benchmark_dir = get_next_generated_benchmarks_dir()
  logging.info('Setting benchmark directory to %s.', benchmark_dir)
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
    benchmarks = introspector.populate_benchmarks_using_introspector(
        project, 'cpp', args.generate_benchmarks_max, benchmark_oracles)
    if benchmarks:
      benchmarklib.Benchmark.to_yaml(benchmarks, benchmark_dir)


def get_experiment_configs(
    args: argparse.Namespace
) -> list[tuple[benchmarklib.Benchmark, argparse.Namespace]]:
  """Constructs a list of experiment configs based on the |BENCHMARK_DIR| and
    |args| setting."""
  benchmark_yamls = []
  if args.benchmark_yaml:
    print(f'A benchmark yaml file ({args.benchmark_yaml}) is provided. '
          f'Will use it and ignore the files in {args.benchmarks_directory}.')
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

  return [(config, args) for config in experiment_configs]


def run_experiments(benchmark: benchmarklib.Benchmark,
                    args: argparse.Namespace) -> Result:
  """Runs an experiment based on the |benchmark| config."""
  try:
    work_dirs = WorkDirs(os.path.join(args.work_dir, f'output-{benchmark.id}'))
    model = models.LLM.setup(
        ai_binary=args.ai_binary,
        name=args.model,
        max_tokens=MAX_TOKENS,
        num_samples=args.num_samples,
        temperature=args.temperature,
    )

    result = run_one_experiment.run(
        benchmark=benchmark,
        model=model,
        template_dir=args.template_directory,
        work_dirs=work_dirs,
        cloud_experiment_name=args.cloud_experiment_name,
        cloud_experiment_bucket=args.cloud_experiment_bucket,
        use_context=args.context,
        run_timeout=args.run_timeout)
    return Result(benchmark, result)
  except Exception as e:
    print('Exception while running experiment:', e, file=sys.stderr)
    traceback.print_exc()
    return Result(benchmark, f'Exception while running experiment: {e}')


def parse_args() -> argparse.Namespace:
  """Parses command line arguments."""
  parser = argparse.ArgumentParser(
      description='Run all experiments that evaluates all target functions.')
  parser.add_argument('-n',
                      '--num-samples',
                      type=int,
                      default=NUM_SAMPLES,
                      help='The number of samples to request from LLM.')
  parser.add_argument(
      '-t',
      '--temperature',
      type=float,
      default=TEMPERATURE,
      help=('A value between 0 and 1 representing the variety of the targets '
            'generated by LLM.'))
  parser.add_argument('-c',
                      '--cloud-experiment-name',
                      type=str,
                      default='',
                      help='The name of the cloud experiment')
  parser.add_argument('-cb',
                      '--cloud-experiment-bucket',
                      type=str,
                      default='',
                      help='A gcloud bucket to store experiment files.')
  parser.add_argument('-b', '--benchmarks-directory', type=str)
  parser.add_argument('-y',
                      '--benchmark-yaml',
                      type=str,
                      help='A benchmark YAML file')
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
                            f'{", ".join(models.LLM.all_llm_names())}'))
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
      '-g',
      '--generate-benchmarks',
      help=('Generate benchmarks and use those for analysis. This is a string '
            'of comma-separated heuristics to use when identifying benchmark '
            'targets. Options available: '
            f'{", ".join(introspector.get_oracle_dict().keys())}'),
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

  args = parser.parse_args()
  if args.num_samples:
    assert args.num_samples > 0, '--num-samples must take a positive integer.'

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


def _print_experiment_result(result: Result):
  """Prints the |result| of a single experiment."""
  print(f'\n**** Finished benchmark {result.benchmark.project}, '
        f'{result.benchmark.function_signature} ****\n'
        f'{result.result}')


def _print_experiment_results(results: list[Result]):
  """Prints the |results| of multiple experiments."""
  print('\n\n**** FINAL RESULTS: ****\n\n')
  for result in results:
    print('=' * 80)
    print(f'*{result.benchmark.project}, {result.benchmark.function_signature}*'
          f'\n{result.result}\n')


def main():
  logging.basicConfig(level=logging.INFO)
  args = parse_args()
  run_one_experiment.prepare()

  experiment_configs = get_experiment_configs(args)
  experiment_results = []

  introspector.set_introspector_endpoints(args.introspector_endpoint)

  print(f'Running {NUM_EXP} experiment(s) in parallel.')
  if NUM_EXP == 1:
    for config in experiment_configs:
      result = run_experiments(*config)
      experiment_results.append(result)
      _print_experiment_result(result)
  else:
    experiment_tasks = []
    with Pool(NUM_EXP) as p:
      for config in experiment_configs:
        experiment_task = p.apply_async(run_experiments,
                                        config,
                                        callback=_print_experiment_result)
        experiment_tasks.append(experiment_task)
        time.sleep(args.delay)
      experiment_results = [task.get() for task in experiment_tasks]

  _print_experiment_results(experiment_results)


if __name__ == '__main__':
  sys.exit(main())
