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
from typing import Any, Dict, List, Optional

import jinja2
import yaml

import run_one_experiment
from experiment import evaluator
from experiment.workdir import WorkDirs

BENCHMARK_SET_DIR = 'benchmark-sets'
BENCHMARK_DIR = ''

MAX_RUN_LOGS_LEN = 16 * 1024

TARGET_EXTS = ('.c', '.cc', '.cpp', '.cxx', '.c++', '.java', '.py')


@dataclasses.dataclass
class Benchmark:
  """The class of a benchmark function and its experiment results."""
  id: str
  status: str
  result: run_one_experiment.AggregatedResult
  signature: str = ''
  project: str = ''
  function: str = ''

  def __post_init__(self):
    self.project = '-'.join(self.id.split('-')[1:-1])
    self.function = self.id.split('-')[-1]
    self.signature = self._find_signature() or self.id

  def _find_signature(self) -> str:
    """
    Finds the function signature by searching for its |benchmark_id| in
    BENCHMARK_DIR.
    """
    project_path = os.path.join(BENCHMARK_DIR, f'{self.project}.yaml')
    if not BENCHMARK_DIR or not os.path.isfile(project_path):
      return ''

    matched_prefix_signature = ''
    with open(project_path) as project_yaml_file:
      functions = yaml.safe_load(project_yaml_file).get('functions', [])
      for function in functions:
        function_name = function.get('name', '')
        function_signature = function.get('signature', '')

        # Best match is a full match, but sometimes the result directory only
        # has the first n characters of a long function name so a full match is
        # not possible.
        # To avoid returning early on a prefix match when there is a full match
        # farther down the list, we only return the prefix match at the end.
        if function_name.lower() == self.function.lower():
          return function_signature
        if function_name.lower().startswith(self.function.lower()):
          if matched_prefix_signature:
            logging.warning(
                'Multiple substring matches found when looking for function '
                'name %s', function_name)
          matched_prefix_signature = function_signature

    return matched_prefix_signature


@dataclasses.dataclass
class Sample:
  """Result of a fuzz target sample of a benchmark."""
  id: str
  status: str
  result: evaluator.Result

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


class Results:

  def __init__(self, results_dir='results'):
    self._results_dir = results_dir

  def list_benchmark_ids(self):
    return sorted(
        filter(self._is_valid_benchmark_dir, os.listdir(self._results_dir)))

  def list_benchmarks(self) -> List[Benchmark]:
    """Lists benchmarks in the result directory."""
    benchmarks = []
    for benchmark in self.list_benchmark_ids():
      results, targets = self._get_results(benchmark)
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

  def match_benchmark(self, benchmark_id: str) -> Benchmark:
    """Returns a benchmark class based on |benchmark_id|."""
    results, targets = self._get_results(benchmark_id)
    status = 'Done' if results and all(results) else 'Running'
    filtered_results = [(i, stat) for i, stat in enumerate(results) if stat]

    if filtered_results:
      result = run_one_experiment.aggregate_results(filtered_results, targets)
    else:
      result = run_one_experiment.AggregatedResult()

    return Benchmark(benchmark_id, status, result)

  def get_final_target_code(self, benchmark: str, sample: str) -> str:
    """Gets the targets of benchmark |benchmark| with sample ID |sample|."""
    targets_dir = os.path.join(self._results_dir, benchmark, 'fixed_targets')

    for name in sorted(os.listdir(targets_dir)):
      path = os.path.join(targets_dir, name)
      if os.path.isfile(path) and name.startswith(sample + '.'):
        with open(path) as f:
          code = f.read()
          code = json.dumps(code)
        return code
    return ''

  def match_sample(self, benchmark: str,
                   target_sample_id: str) -> Optional[Sample]:
    """Identifies the samples object and its status of the given sample id."""
    results, _ = self._get_results(benchmark)

    for i, sample_id in enumerate(
        self._sample_ids(self._get_generated_targets(benchmark))):
      if sample_id != target_sample_id:
        continue
      status = 'Running'
      result = evaluator.Result()
      if results[i]:
        status = 'Done'
        result = results[i]

      return Sample(sample_id, status, result)
    logging.warning('Failed to identify benchmark sample: %s\n  %s', benchmark,
                    target_sample_id)
    return None

  def get_logs(self, benchmark: str, sample: str) -> str:
    status_dir = os.path.join(self._results_dir, benchmark, 'status')
    results_path = os.path.join(status_dir, sample, 'log.txt')
    if not os.path.exists(results_path):
      return ''

    with open(results_path) as f:
      return f.read()

  def get_run_logs(self, benchmark: str, sample: str) -> str:
    """Returns the content of the last run log."""
    run_logs_dir = os.path.join(self._results_dir, benchmark, 'logs', 'run')
    largest_iteration, last_log_file = -1, None
    for name in os.listdir(run_logs_dir):
      if name.startswith(sample + '.'):
        iteration = WorkDirs.get_run_log_iteration(name)
        if iteration is None:
          # Be compatible with older results where no '-Fxx' in run log file name
          last_log_file = name
          break

        if largest_iteration < iteration:
          largest_iteration, last_log_file = iteration, name

    if not last_log_file:
      return ''

    with open(os.path.join(run_logs_dir, last_log_file), errors='replace') as f:
      return self._truncate_logs(f.read(), MAX_RUN_LOGS_LEN)

    return ''

  def get_targets(self, benchmark: str, sample: str) -> list[Target]:
    """Gets the targets of benchmark |benchmark| with sample ID |sample|."""
    targets_dir = os.path.join(self._results_dir, benchmark, 'fixed_targets')
    targets = []

    for name in sorted(os.listdir(targets_dir)):
      path = os.path.join(targets_dir, name)
      if os.path.isfile(path) and name.startswith(sample + '.'):
        logging.debug(path)
        with open(path) as f:
          code = f.read()
        targets.insert(0, Target(code=code))

      if os.path.isdir(path) and name.startswith(sample + '-F'):
        targets.append(self._get_fixed_target(path))

    return targets

  def get_samples(self, benchmark: str) -> list[Sample]:
    """Gets the samples and their status of the given benchmark |bnmk|."""
    samples = []
    results, _ = self._get_results(benchmark)

    for i, sample_id in enumerate(
        self._sample_ids(self._get_generated_targets(benchmark))):
      status = 'Running'
      result = evaluator.Result()
      if results[i]:
        status = 'Done'
        result = results[i]

      samples.append(Sample(sample_id, status, result))

    return samples

  def get_prompt(self, benchmark: str) -> Optional[str]:
    root_dir = os.path.join(self._results_dir, benchmark)
    for name in os.listdir(root_dir):
      if re.match(r'^prompt.*txt$', name):
        with open(os.path.join(root_dir, name)) as f:
          content = f.read()

        # Prepare prompt text for HTML.
        return self._prepare_prompt_for_html_text(content)

    return None

  def _get_results(self,
                   benchmark: str) -> tuple[list[evaluator.Result], list[str]]:
    """
    Returns results of all samples. Items can be None if they're not complete.
    """
    targets = self._get_generated_targets(benchmark)

    results = []
    status_dir = os.path.join(self._results_dir, benchmark, 'status')

    for sample_id in self._sample_ids(targets):
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

  def _prepare_prompt_for_html_text(self, raw_prompt_content: str) -> str:
    """Converts a raw prompt file into presentable HTML text."""
    try:
      structured_prompt = json.loads(raw_prompt_content)
      if isinstance(structured_prompt, list) and structured_prompt:
        html_presentable_content = ''
        for elem in structured_prompt:
          if isinstance(elem, dict) and 'content' in elem:
            html_presentable_content += f'\n{elem["content"]}'
        logging.debug('Converted structured prompt to raw text.')
        return html_presentable_content
    except json.decoder.JSONDecodeError:
      logging.debug('Using raw prompt text.')
      pass

    # If execution goes here it the input was not a structured prompt but just
    # raw text, which is then returned.
    return raw_prompt_content

  def _is_valid_benchmark_dir(self, cur_dir: str) -> bool:
    """Checks if |cur_dir| is a valid benchmark directory (e.g., no lost+found)"""
    # Check prefix.
    if not cur_dir.startswith('output-'):
      return False
    # Check sub-directories.
    expected_dirs = ['raw_targets', 'status', 'fixed_targets']
    return all(
        os.path.isdir(os.path.join(self._results_dir, cur_dir, expected_dir))
        for expected_dir in expected_dirs)

  def _get_generated_targets(self, benchmark: str) -> list[str]:
    targets = []
    raw_targets_dir = os.path.join(self._results_dir, benchmark, 'raw_targets')
    for filename in sorted(os.listdir(raw_targets_dir)):
      if os.path.splitext(filename)[1] in TARGET_EXTS:
        targets.append(os.path.join(raw_targets_dir, filename))

    return targets

  def _get_fixed_target(self, path: str):
    """Gets the fixed fuzz target from the benchmark's result |path|."""
    code = ''
    fixer_prompt = ''
    for name in os.listdir(path):
      if name.endswith('.txt'):
        with open(os.path.join(path, name)) as f:
          fixer_prompt = f.read()

      # Prepare prompt for being used in HTML.
      fixer_prompt = self._prepare_prompt_for_html_text(fixer_prompt)

      if name.endswith('.rawoutput'):
        with open(os.path.join(path, name)) as f:
          code = f.read()

    return Target(code, fixer_prompt)

  def _sample_ids(self, target_paths: list[str]):
    for target in target_paths:
      yield os.path.splitext(os.path.basename(target))[0]

  def _truncate_logs(self, logs: str, max_len: int) -> str:
    if len(logs) <= max_len:
      return logs

    return logs[:max_len // 2] + '\n...truncated...\n' + logs[-(max_len // 2) +
                                                              1:]


class JinjaTemplate:

  @staticmethod
  def _urlencode_filter(s):
    return urllib.parse.quote(s, safe='')

  @staticmethod
  def _percent(num: float):
    return '%0.2f' % (num * 100)

  @staticmethod
  def _cov_report_link(link: str):
    if not link:
      return '#'

    path = link.removeprefix('gs://oss-fuzz-gcb-experiment-run-logs/')
    return f'https://llm-exp.oss-fuzz.com/{path}/report/linux/report.html'

  def __init__(self, template_globals: Dict[str, Any] = {}):
    self._env = jinja2.Environment(
        loader=jinja2.FileSystemLoader("report/templates"),
        autoescape=jinja2.select_autoescape())

    self._env.filters['urlencode_filter'] = self._urlencode_filter
    self._env.filters['percent'] = self._percent
    self._env.filters['cov_report_link'] = self._cov_report_link

    for key, val in template_globals.items():
      self._env.globals[key] = val

  def render(self, template_name: str, **kwargs):
    return self._env.get_template(template_name).render(**kwargs)


class GenerateReport:

  def __init__(self,
               results: Results,
               output_dir: str = 'results-report',
               template_globals: Dict[str, Any] = {}):
    self._results = results
    self._output_dir = output_dir
    self._jinja = JinjaTemplate(template_globals=template_globals)

  def generate(self):
    self._write_index_html()
    self._write_index_json()
    for benchmark in self._results.list_benchmark_ids():
      self._write_benchmark_index(benchmark)
      self._write_benchmark_crash(benchmark)
      for sample in self._results.get_samples(benchmark):
        self._write_benchmark_sample(benchmark, sample.id)

  def _write(self, output_path: str, content: str):
    full_path = os.path.join(self._output_dir, output_path)

    parent_dir = os.path.dirname(full_path)
    if not os.path.exists(parent_dir):
      os.makedirs(parent_dir)

    if not os.path.isdir(parent_dir):
      raise Exception(
          f'Writing to {full_path} but {parent_dir} is not a directory!')

    with open(full_path, 'w', encoding='utf-8') as f:
      f.write(content)

  def _write_index_html(self):
    rendered = self._jinja.render('index.html',
                                  benchmarks=self._results.list_benchmarks())
    self._write('index.html', rendered)

  def _write_index_json(self):
    rendered = self._jinja.render('index.json',
                                  benchmarks=self._results.list_benchmarks())
    self._write('index.json', rendered)

  def _write_benchmark_index(self, benchmark_id: str):
    rendered = self._jinja.render(
        'benchmark.html',
        benchmark=benchmark_id,
        samples=self._results.get_samples(benchmark_id),
        prompt=self._results.get_prompt(benchmark_id))
    self._write(f'benchmark/{benchmark_id}/index.html', rendered)

  def _write_benchmark_crash(self, benchmark_id: str):
    try:
      rendered = self._jinja.render(
          'crash.json',
          benchmark=self._results.match_benchmark(benchmark_id).signature,
          samples=self._results.get_samples(benchmark_id),
          get_benchmark_final_target_code=partial(
              self._results.get_final_target_code, benchmark_id))
      self._write(f'benchmark/{benchmark_id}/crash.json', rendered)
    except Exception as e:
      print(f'Failed to write benchmark/{benchmark_id}/crash.json:\n{e}')

  def _write_benchmark_sample(self, benchmark_id: str, sample_id: str):
    try:
      rendered = self._jinja.render(
          'sample.html',
          benchmark=benchmark_id,
          sample=self._results.match_sample(benchmark_id, sample_id),
          logs=self._results.get_logs(benchmark_id, sample_id),
          run_logs=self._results.get_run_logs(benchmark_id, sample_id),
          targets=self._results.get_targets(benchmark_id, sample_id))
      self._write(f'sample/{benchmark_id}/{sample_id}', rendered)
    except Exception as e:
      print(f'Failed to write sample/{benchmark_id}/{sample_id}:\n{e}')


if __name__ == '__main__':
  # TODO(Dongge): Use argparser as this script gets more complex.
  results_dir = sys.argv[1]
  benchmark_set = sys.argv[2] if len(sys.argv) > 2 else ''
  model = sys.argv[3] if len(sys.argv) > 3 else ''
  output_dir = sys.argv[4] if len(sys.argv) > 4 else 'results-report'

  if benchmark_set:
    BENCHMARK_DIR = os.path.join(BENCHMARK_SET_DIR, benchmark_set)

  results = Results(results_dir=results_dir)
  gr = GenerateReport(results=results,
                      output_dir=output_dir,
                      template_globals={'model': model})
  gr.generate()
