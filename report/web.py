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
"""Report generation tool to create HTML reports for experiment result."""

import argparse
import json
import logging
import os
import threading
import time
import urllib.parse
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, List, Optional

import jinja2

from report.common import (AccumulatedResult, Benchmark, FileSystem, Results,
                           Sample, Target)

LOCAL_HOST = '127.0.0.1'


class JinjaEnv:
  """JinjaEnv wraps the set up of a jinja2 environment."""

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

  def __init__(self, template_globals: Optional[Dict[str, Any]] = None):
    self._env = jinja2.Environment(
        loader=jinja2.FileSystemLoader("report/templates"),
        autoescape=jinja2.select_autoescape())

    self._env.filters['urlencode_filter'] = self._urlencode_filter
    self._env.filters['percent'] = self._percent
    self._env.filters['cov_report_link'] = self._cov_report_link

    if template_globals:
      for key, val in template_globals.items():
        self._env.globals[key] = val

  def render(self, template_name: str, **kwargs):
    """Render a template with variables provides through kwargs."""
    return self._env.get_template(template_name).render(**kwargs)


class GenerateReport:
  """
  GenerateReport helps generate an HTML report of experiment results.

  Args:
    results: A Results object which takes care of reading results files and
      processing them for the HTML templates.
    output_dir: The directory to for the HTML report files.
    jinja_env: A JinjaEnv object which provides the template render function.
  """

  def __init__(self,
               results: Results,
               jinja_env: JinjaEnv,
               results_dir: str,
               output_dir: str = 'results-report'):
    self._results = results
    self._output_dir = output_dir
    self._jinja = jinja_env
    self.results_dir = results_dir

  def read_timings(self):
    with open(os.path.join(self.results_dir, 'report.json'), 'r') as f:
      timings_dict = json.loads(f.read())
    return timings_dict

  def generate(self):
    """Generate and write every report file."""
    benchmarks = []
    for benchmark_id in self._results.list_benchmark_ids():
      results, targets = self._results.get_results(benchmark_id)
      benchmark = self._results.match_benchmark(benchmark_id, results, targets)
      benchmarks.append(benchmark)
      samples = self._results.get_samples(results, targets)
      prompt = self._results.get_prompt(benchmark.id)

      self._write_benchmark_index(benchmark, samples, prompt)
      self._write_benchmark_crash(benchmark, samples)

      for sample in samples:
        sample_targets = self._results.get_targets(benchmark.id, sample.id)
        self._write_benchmark_sample(benchmark, sample, sample_targets)

    accumulated_results = self._results.get_macro_insights(benchmarks)

    time_results = self.read_timings()

    self._write_index_html(benchmarks, accumulated_results, time_results)
    self._write_index_json(benchmarks)

  def _write(self, output_path: str, content: str):
    """Utility write to filesystem function."""
    full_path = os.path.join(self._output_dir, output_path)

    parent_dir = os.path.dirname(full_path)
    if not FileSystem(parent_dir).exists():
      FileSystem(parent_dir).makedirs()

    if not FileSystem(parent_dir).isdir():
      raise Exception(
          f'Writing to {full_path} but {parent_dir} is not a directory!')

    with FileSystem(full_path).open('w', encoding='utf-8') as f:
      f.write(content)

  def _write_index_html(self, benchmarks: List[Benchmark],
                        accumulated_results: AccumulatedResult,
                        time_results: dict[str, Any]):
    """Generate the report index.html and write to filesystem."""
    rendered = self._jinja.render('index.html',
                                  benchmarks=benchmarks,
                                  accumulated_results=accumulated_results,
                                  time_results=time_results)
    self._write('index.html', rendered)

  def _write_index_json(self, benchmarks: List[Benchmark]):
    """Generate the report index.json and write to filesystem."""
    rendered = self._jinja.render('index.json', benchmarks=benchmarks)
    self._write('index.json', rendered)

  def _write_benchmark_index(self, benchmark: Benchmark, samples: List[Sample],
                             prompt: Optional[str]):
    """Generate the benchmark index.html and write to filesystem."""
    rendered = self._jinja.render('benchmark.html',
                                  benchmark=benchmark.id,
                                  samples=samples,
                                  prompt=prompt)
    self._write(f'benchmark/{benchmark.id}/index.html', rendered)

  def _write_benchmark_crash(self, benchmark: Benchmark, samples: List[Sample]):
    """Generate the benchmark crash.json and write to filesystem."""
    try:
      rendered = self._jinja.render('crash.json',
                                    benchmark=benchmark.signature,
                                    samples=samples,
                                    get_benchmark_final_target_code=partial(
                                        self._results.get_final_target_code,
                                        benchmark.id))
      self._write(f'benchmark/{benchmark.id}/crash.json', rendered)
    except Exception as e:
      logging.error('Failed to write benchmark/%s/crash.json:\n%s',
                    benchmark.id, e)

  def _write_benchmark_sample(self, benchmark: Benchmark, sample: Sample,
                              sample_targets: List[Target]):
    """Generate the sample page and write to filesystem."""
    try:
      rendered = self._jinja.render(
          'sample.html',
          benchmark=benchmark.id,
          sample=sample,
          logs=self._results.get_logs(benchmark.id, sample.id),
          run_logs=self._results.get_run_logs(benchmark.id, sample.id),
          triage=self._results.get_triage(benchmark.id, sample.id),
          targets=sample_targets)
      self._write(f'sample/{benchmark.id}/{sample.id}.html', rendered)
    except Exception as e:
      logging.error('Failed to write sample/%s/%s:\n%s', benchmark.id,
                    sample.id, e)


def generate_report(args: argparse.Namespace) -> None:
  """Generates static web server files."""
  logging.info('Generating web page files in %s', args.output_dir)
  results = Results(results_dir=args.results_dir,
                    benchmark_set=args.benchmark_set)
  jinja_env = JinjaEnv(template_globals={'model': args.model})
  gr = GenerateReport(results=results,
                      jinja_env=jinja_env,
                      results_dir=args.results_dir,
                      output_dir=args.output_dir)
  gr.generate()


def launch_webserver(args):
  """Launches a local web server to browse results."""
  logging.info('Launching webserver at %s:%d', LOCAL_HOST, args.port)
  server = ThreadingHTTPServer((LOCAL_HOST, args.port),
                               partial(SimpleHTTPRequestHandler,
                                       directory=args.output_dir))
  server.serve_forever()


def _parse_arguments() -> argparse.Namespace:
  """Parses command line args."""
  parser = argparse.ArgumentParser(description=(
      'Report generation tool reads raw experiment output files and '
      'generates a report in the form of HTML files in a directory hierarchy.'))

  parser.add_argument('--results-dir',
                      '-r',
                      help='Directory with results from OSS-Fuzz-gen.',
                      required=True)
  parser.add_argument(
      '--output-dir',
      '-o',
      help='Directory to store statically generated web report.',
      default='results-report')
  parser.add_argument('--benchmark-set',
                      '-b',
                      help='Directory with benchmarks used for the experiment.',
                      default='')
  parser.add_argument('--model',
                      '-m',
                      help='Model used for the experiment.',
                      default='')
  parser.add_argument('--serve',
                      '-s',
                      help='Will launch a web server if set.',
                      action='store_true')
  parser.add_argument('--port',
                      '-p',
                      help='Port to launch webserver on.',
                      type=int,
                      default=8012)

  return parser.parse_args()


def main():
  args = _parse_arguments()

  if not args.serve:
    generate_report(args)
  else:
    logging.getLogger().setLevel(os.environ.get('LOGLEVEL', 'INFO').upper())
    # Launch web server
    thread = threading.Thread(target=launch_webserver, args=(args,))
    thread.start()

    # Generate results continuously while the process runs.
    while True:
      generate_report(args)
      try:
        time.sleep(90)
      except KeyboardInterrupt:
        logging.info('Exiting.')
        os._exit(0)


if __name__ == '__main__':
  logging.getLogger().setLevel(os.environ.get('LOGLEVEL', 'WARN').upper())
  main()
