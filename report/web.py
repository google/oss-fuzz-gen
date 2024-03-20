#!/usr/bin/env python
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
"""A local server to visualize experiment result."""

import dataclasses
import json
import logging
import os
import re
import sys
import urllib.parse
from functools import partial
from typing import List, Optional

import yaml
from flask import Flask, abort, render_template

import run_one_experiment
from experiment import evaluator

app = Flask(__name__)
# Disable Flask request logs
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

RESULTS_DIR = ''
BENCHMARK_SET_DIR = 'benchmark-sets'
BENCHMARK_DIR = ''

MAX_RUN_LOGS_LEN = 16 * 1024


@dataclasses.dataclass
class Benchmark:
  """The class of a benchmark function and its experiment results."""
  id: str
  status: str
  result: run_one_experiment.AggregatedResult
  signature: str = ''

  def __post_init__(self):
    self.signature = self._find_signature(self.id) or self.id

  @staticmethod
  def find_signature(benchmark_id: str) -> str:
    """Finds the function signature by searching for its benchmark_id in BENCHMARK_DIR."""
    if not BENCHMARK_DIR:
      return ''

    for project_yaml in os.listdir(BENCHMARK_DIR):
      yaml_project_name = project_yaml.removesuffix(".yaml")
      with open(os.path.join(BENCHMARK_DIR, project_yaml)) as project_yaml_file:
        if yaml_project_name not in benchmark_id:
          continue
        functions = yaml.safe_load(project_yaml_file).get('functions', [])
        for function in functions:
          function_name = benchmark_id.removeprefix(
              f'output-{yaml_project_name}-')
          if function.get('name', '').lower().startswith(function_name):
            return f'{yaml_project_name}-{function.get("signature", "")}'

    return ''


@dataclasses.dataclass
class Sample:
  """Result of a fuzz target sample of a benchmark."""
  id: str
  status: str
  result: Optional[evaluator.Result] = None

  @property
  def stacktrace(self) -> str:
    if not self.result:
      return ''
    reproducer_link = self.result.reproducer_path
    return f'{reproducer_link}/stacktrace'

  @property
  def target_binary(self) -> str:
    if not self.result:
      return ''
    reproducer_link = self.result.reproducer_path
    return f'{reproducer_link}/target_binary'

  @property
  def reproducer(self) -> str:
    if not self.result:
      return ''
    reproducer_link = self.result.reproducer_path
    return f'{reproducer_link}/artifacts'

  @property
  def run_log(self) -> str:
    if not self.result:
      return ''
    reproducer_link = self.result.reproducer_path
    return reproducer_link.removesuffix('reproducer') + 'run.log'


@dataclasses.dataclass
class Target:
  code: str
  fixer_prompt: Optional[str] = None


def sample_ids(target_paths: list[str]):
  for target in target_paths:
    yield os.path.splitext(os.path.basename(target))[0]


def get_results(benchmark) -> tuple[list[evaluator.Result], list[str]]:
  """
  Returns results of all samples. Items can be None if they're not complete.
  """
  targets = get_generated_targets(benchmark)

  results = []
  status_dir = os.path.join(RESULTS_DIR, benchmark, 'status')

  for sample_id in sample_ids(targets):
    results_path = os.path.join(status_dir, sample_id, 'result.json')
    if not os.path.exists(results_path):
      results.append(None)
      continue

    with open(results_path) as f:
      try:
        data = json.load(f)
      except Exception:
        return [], []

    results.append(evaluator.Result(**data))

  return results, targets


def get_prompt(benchmark) -> Optional[str]:
  root_dir = os.path.join(RESULTS_DIR, benchmark)
  for name in os.listdir(root_dir):
    if re.match(r'^prompt.*txt$', name):
      with open(os.path.join(root_dir, name)) as f:
        return f.read()

  return None


def get_generated_targets(benchmark: str) -> list[str]:
  targets = []
  raw_targets_dir = os.path.join(RESULTS_DIR, benchmark, 'raw_targets')
  for filename in sorted(os.listdir(raw_targets_dir)):
    if os.path.splitext(filename)[1] in ('.c', '.cc', '.cpp', '.cxx'):
      targets.append(os.path.join(raw_targets_dir, filename))

  return targets


def _is_valid_benchmark_dir(cur_dir: str) -> bool:
  """Checks if |cur_dir| is a valid benchmark directory (e.g., no lost+found)"""
  # Check prefix.
  if not cur_dir.startswith('output-'):
    return False
  # Check sub-directories.
  expected_dirs = ['raw_targets', 'status', 'fixed_targets']
  return all(
      os.path.isdir(os.path.join(RESULTS_DIR, cur_dir, expected_dir))
      for expected_dir in expected_dirs)


def list_benchmarks() -> List[Benchmark]:
  """Lists benchmarks in the result directory."""
  benchmarks = []
  benchmark_names = sorted(os.listdir(RESULTS_DIR))
  # Not sure why there is a `lost+found` dir in |RESULTS_DIR|, which caused
  # failures in get_generated_targets().
  # Maybe it is from mounting?
  # TODO(erfan): Check if not mounting to the root dir can solve this.
  for benchmark in benchmark_names:
    if not _is_valid_benchmark_dir(benchmark):
      continue
    results, targets = get_results(benchmark)
    status = 'Done' if all(r for r in results) and results else 'Running'

    filtered_results = []
    for i, stat in enumerate(results):
      if stat:
        filtered_results.append((i, stat))

    if filtered_results:
      result = run_one_experiment.aggregate_results(filtered_results, targets)
    else:
      result = run_one_experiment.AggregatedResult()

    benchmarks.append(Benchmark(benchmark, status, result))

  return benchmarks


def sort_benchmarks(benchmarks: List[Benchmark]) -> List[Benchmark]:
  """Keeps benchmarks with the highest line coverage diff on the top."""
  sorted_benchmarks = sorted(benchmarks,
                             key=lambda b: b.result.max_line_coverage_diff,
                             reverse=True)
  return sorted_benchmarks


def get_samples(benchmark: str) -> list[Sample]:
  """Gets the samples and their status of the given benchmark |bnmk|."""
  samples = []
  results, _ = get_results(benchmark)

  for i, sample_id in enumerate(sample_ids(get_generated_targets(benchmark))):
    status = 'Running'
    result = None
    if results[i]:
      status = 'Done'
      result = results[i]

    samples.append(Sample(sample_id, status, result))

  return samples


def truncate_logs(logs: str, max_len: int) -> str:
  if len(logs) <= max_len:
    return logs

  return logs[:max_len // 2] + '\n...truncated...\n' + logs[-(max_len // 2) +
                                                            1:]


def get_logs(benchmark: str, sample: str) -> str:
  status_dir = os.path.join(RESULTS_DIR, benchmark, 'status')
  results_path = os.path.join(status_dir, sample, 'log.txt')
  if not os.path.exists(results_path):
    return ''

  with open(results_path) as f:
    return f.read()


def get_run_logs(benchmark: str, sample: str) -> str:
  run_logs_dir = os.path.join(RESULTS_DIR, benchmark, 'logs', 'run')
  for name in os.listdir(run_logs_dir):
    if name.startswith(sample + '.'):
      with open(os.path.join(run_logs_dir, name), errors='replace') as f:
        return truncate_logs(f.read(), MAX_RUN_LOGS_LEN)

  return ''


def get_fixed_target(path):
  """Gets the fixed fuzz target from the benchmark's result |path|."""
  code = ''
  fixer_prompt = ''
  for name in os.listdir(path):
    if name.endswith('.txt'):
      with open(os.path.join(path, name)) as f:
        fixer_prompt = f.read()

    if name.endswith('.rawoutput'):
      with open(os.path.join(path, name)) as f:
        code = f.read()

  return Target(code, fixer_prompt)


def get_targets(benchmark: str, sample: str) -> list[Target]:
  """Gets the targets of benchmark |benchmark| with sample ID |sample|."""
  targets_dir = os.path.join(RESULTS_DIR, benchmark, 'fixed_targets')
  targets = []

  for name in sorted(os.listdir(targets_dir)):
    path = os.path.join(targets_dir, name)
    if os.path.isfile(path) and name.startswith(sample + '.'):
      logging.debug(path)
      with open(path) as f:
        code = f.read()
      targets.insert(0, Target(code=code))

    if os.path.isdir(path) and name.startswith(sample + '-F'):
      targets.append(get_fixed_target(path))

  return targets


def get_final_target_code(benchmark: str, sample: str) -> str:
  """Gets the targets of benchmark |benchmark| with sample ID |sample|."""
  targets_dir = os.path.join(RESULTS_DIR, benchmark, 'fixed_targets')

  for name in sorted(os.listdir(targets_dir)):
    path = os.path.join(targets_dir, name)
    if os.path.isfile(path) and name.startswith(sample + '.'):
      with open(path) as f:
        code = f.read()
        code = json.dumps(code)
      return code
  return ''


@app.route('/')
def index():
  return render_template('index.html',
                         benchmarks=list_benchmarks(),
                         model=model)


@app.route('/json')
def index_json():
  return render_template('index.json',
                         benchmarks=list_benchmarks(),
                         model=model)


@app.route('/sort')
def index_sort():
  return render_template('index.html',
                         benchmarks=sort_benchmarks(list_benchmarks()),
                         model=model)


@app.route('/benchmark/<benchmark>/crash.json')
def benchmark_json(benchmark):
  """Generates a JSON containing crash reproducing info."""
  if not _is_valid_benchmark_dir(benchmark):
    # TODO(dongge): This won't be needed after resolving the `lost+found` issue.
    abort(404)

  try:
    return render_template('benchmark.json',
                           benchmark=Benchmark.find_signature(benchmark),
                           samples=get_samples(benchmark),
                           get_benchmark_final_target_code=partial(
                               get_final_target_code, benchmark),
                           model=model)
  except Exception as e:
    logging.warning('Failed to render benchmark crash JSON: %s\n  %s',
                    benchmark, e)
    return ''


@app.route('/benchmark/<benchmark>')
def benchmark_page(benchmark):
  if _is_valid_benchmark_dir(benchmark):
    return render_template('benchmark.html',
                           benchmark=benchmark,
                           samples=get_samples(benchmark),
                           prompt=get_prompt(benchmark),
                           model=model)
  # TODO(dongge): This won't be needed after resolving the `lost+found` issue.
  abort(404)


@app.route('/sample/<benchmark>/<sample>')
def sample_page(benchmark, sample):
  """Renders each fuzz target |sample| of the |benchmark|."""
  if _is_valid_benchmark_dir(benchmark):
    return render_template('sample.html',
                           benchmark=benchmark,
                           sample=sample,
                           logs=get_logs(benchmark, sample),
                           run_logs=get_run_logs(benchmark, sample),
                           targets=get_targets(benchmark, sample),
                           model=model)
  # TODO(dongge): This won't be needed after resolving the `lost+found` issue.
  abort(404)


# Define a custom filter for Jinja2
@app.template_filter('urlencode')
def urlencode_filter(s):
  return urllib.parse.quote(s, safe='')


@app.template_filter()
def percent(num: float):
  return '%0.2f' % (num * 100)


@app.template_filter()
def cov_report_link(link: str):
  if not link:
    return '#'

  path = link.removeprefix('gs://oss-fuzz-gcb-experiment-run-logs/')
  return f'https://llm-exp.oss-fuzz.com/{path}/report/linux/report.html'


def serve(directory: str, port: int, benchmark_set: str):
  global RESULTS_DIR, BENCHMARK_DIR
  RESULTS_DIR = directory
  if benchmark_set:
    BENCHMARK_DIR = os.path.join(BENCHMARK_SET_DIR, benchmark_set)
  app.run(host='localhost', port=port)


if __name__ == '__main__':
  # TODO(Dongge): Use argparser as this script gets more complex.
  results_dir = sys.argv[1]
  server_port = int(sys.argv[2])
  benchmark_dir = sys.argv[3] if len(sys.argv) > 3 else ''
  model = sys.argv[4] if len(sys.argv) > 4 else ''

  serve(results_dir, server_port, benchmark_dir)
