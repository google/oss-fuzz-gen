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

import dataclasses
import json
import logging
import os
import re
import sys
from typing import List, Optional

from flask import Flask, render_template

import run_one_experiment
from experiment import evaluator

app = Flask(__name__)
# Disable Flask request logs
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

RESULTS_DIR = ''

MAX_RUN_LOGS_LEN = 16 * 1024


@dataclasses.dataclass
class Benchmark:
  id: str
  status: str
  result: run_one_experiment.AggregatedResult


@dataclasses.dataclass
class Sample:
  id: str
  status: str
  result: Optional[evaluator.Result] = None


@dataclasses.dataclass
class Target:
  code: str
  fixer_prompt: Optional[str] = None


def sample_ids(target_paths: list[str]):
  for target in target_paths:
    yield os.path.splitext(os.path.basename(target))[0]


def get_results(benchmark) -> tuple[list[evaluator.Result], list[str]]:
  """Return results of all samples. Items can be None if they're not complete."""
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


def list_benchmarks() -> List[Benchmark]:
  benchmarks = []
  benchmark_names = sorted(os.listdir(RESULTS_DIR))
  for benchmark in benchmark_names:
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
  targets_dir = os.path.join(RESULTS_DIR, benchmark, 'fixed_targets')
  targets = []

  for name in sorted(os.listdir(targets_dir)):
    path = os.path.join(targets_dir, name)
    if os.path.isfile(path) and name.startswith(sample + '.'):
      print(path)
      with open(path) as f:
        code = f.read()
      targets.insert(0, Target(code=code))

    if os.path.isdir(path) and name.startswith(sample + '-F'):
      targets.append(get_fixed_target(path))

  return targets


@app.route('/')
def index():
  return render_template('index.html', benchmarks=list_benchmarks())


@app.route('/json')
def index_json():
  return render_template('index.json', benchmarks=list_benchmarks())


@app.route('/sort')
def index_sort():
  return render_template('index.html',
                         benchmarks=sort_benchmarks(list_benchmarks()))


@app.route('/benchmark/<benchmark>')
def benchmark(benchmark):
  return render_template('benchmark.html',
                         benchmark=benchmark,
                         samples=get_samples(benchmark),
                         prompt=get_prompt(benchmark))


@app.route('/sample/<benchmark>/<sample>')
def sample(benchmark, sample):
  return render_template('sample.html',
                         benchmark=benchmark,
                         sample=sample,
                         logs=get_logs(benchmark, sample),
                         run_logs=get_run_logs(benchmark, sample),
                         targets=get_targets(benchmark, sample))


@app.template_filter()
def percent(num: float):
  return '%0.2f' % (num * 100)


@app.template_filter()
def cov_report_link(link: str):
  if not link:
    return '#'

  path = link.removeprefix('gs://oss-fuzz-gcb-experiment-run-logs/')
  return f'https://llm-exp.oss-fuzz.com/{path}/report/linux/report.html'


def serve(results_dir: str, port: int):
  global RESULTS_DIR
  RESULTS_DIR = results_dir
  app.run(host='localhost', port=port)


if __name__ == '__main__':
  results_dir = sys.argv[1]
  port = int(sys.argv[2])

  serve(results_dir, port)
