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
import shutil
import threading
import time
import urllib.parse
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, List, Optional

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import subprocess
import threading


import jinja2

from report.common import (AccumulatedResult, Benchmark, FileSystem, Project,
                           Results, Sample, Target)

LOCAL_HOST = '127.0.0.1'


class JinjaEnv:
  """JinjaEnv wraps the set up of a jinja2 environment."""

  @staticmethod
  def _urlencode_filter(s):
    return urllib.parse.quote(s, safe='')

  @staticmethod
  def _percent(num: float):
    return f'{num*100:.2f}'

  @staticmethod
  def _cov_report_link(link: str):
    """Get URL to coverage report"""
    if not link:
      return '#'

    if 'gcb-experiment' not in link:
      # In local rusn we don't overwrite the path
      link_path = link
    else:
      path = link.removeprefix('gs://oss-fuzz-gcb-experiment-run-logs/')
      link_path = f'https://llm-exp.oss-fuzz.com/{path}/report/linux/'

    # Check if this is a java benchmark, which will always have a period in
    # the path, where C/C++ wont.
    # TODO(David) refactor to have paths for links more controlled.
    if '.' in link_path:
      return link_path + 'index.html'
    return link_path + 'report.html'

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

  def _copy_and_set_coverage_report(self, benchmark, sample):
    """Prepares coverage reports in local runs."""
    coverage_path = os.path.join(self.results_dir, benchmark.id,
                                 'code-coverage-reports')
    if not os.path.isdir(coverage_path):
      return

    coverage_report = ''
    for l in os.listdir(coverage_path):
      if l.split('.')[0] == sample.id:
        coverage_report = os.path.join(coverage_path, l)

    # On cloud runs there are two folders in code coverage reports, (report,
    # textcov). If we have three files/dirs (linux, style.cssand textcov), then
    # it's a local run. In that case copy over the code coverage reports so
    # they are visible in the HTML page.
    if coverage_report and os.path.isdir(coverage_report) and len(
        os.listdir(coverage_report)) > 2:
      # Copy coverage to reports out
      dst = os.path.join(self._output_dir, 'sample', benchmark.id, 'coverage')
      os.makedirs(dst, exist_ok=True)
      dst = os.path.join(dst, sample.id)

      shutil.copytree(coverage_report, dst, dirs_exist_ok=True)
      sample.result.coverage_report_path = \
        f'/sample/{benchmark.id}/coverage/{sample.id}/linux/'

  def generate(self):
    """Generate and write every report file."""
    benchmarks = []
    samples_with_bugs = []
    for benchmark_id in self._results.list_benchmark_ids():
      results, targets = self._results.get_results(benchmark_id)
      benchmark = self._results.match_benchmark(benchmark_id, results, targets)
      benchmarks.append(benchmark)
      samples = self._results.get_samples(results, targets)
      prompt = self._results.get_prompt(benchmark.id)

      for sample in samples:
        # If this is a local run then we need to set up coverage reports.
        self._copy_and_set_coverage_report(benchmark, sample)

      self._write_benchmark_index(benchmark, samples, prompt)
      self._write_benchmark_crash(benchmark, samples)

      for sample in samples:
        if sample.result.crashes:
          samples_with_bugs.append({'benchmark': benchmark, 'sample': sample})
        sample_targets = self._results.get_targets(benchmark.id, sample.id)
        self._write_benchmark_sample(benchmark, sample, sample_targets)

    accumulated_results = self._results.get_macro_insights(benchmarks)
    projects = self._results.get_project_summary(benchmarks)
    coverage_language_gains = self._results.get_coverage_language_gains()

    time_results = self.read_timings()

    self._write_index_html(benchmarks, accumulated_results, time_results,
                           projects, samples_with_bugs, coverage_language_gains)
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
                        time_results: dict[str, Any], projects: list[Project],
                        samples_with_bugs: list[dict[str, Any]],
                        coverage_language_gains: dict[str, Any]):
    """Generate the report index.html and write to filesystem."""
    rendered = self._jinja.render(
        'index.html',
        benchmarks=benchmarks,
        accumulated_results=accumulated_results,
        time_results=time_results,
        projects=projects,
        samples_with_bugs=samples_with_bugs,
        coverage_language_gains=coverage_language_gains)
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

class ReportWatcher(FileSystemEventHandler):
  """Watches for file changes and regenerates reports."""
  
  def __init__(self, args: argparse.Namespace):
    super().__init__()
    self.args = args
    self.observer = Observer()
    self.server_thread = None
    self.server = None  
    
    if args.watch_filesystem:
      self.observer.schedule(self, args.results_dir, recursive=True)
        
    if args.watch_template:
      self.observer.schedule(self, "report/", recursive=True)

    if args.serve:
      self.server_thread = threading.Thread(target=self._start_server)
      self.server_thread.daemon = True
      self.server_thread.start()

  def _start_server(self):
    """Helper method to start the server."""
    handler = partial(SimpleHTTPRequestHandler, directory=self.args.output_dir)
    self.server = ThreadingHTTPServer((LOCAL_HOST, self.args.port), handler)
    self.server.daemon_threads = True
    self.server.allow_reuse_address = True
    self.server.serve_forever()

  def start(self):
    """Start watching if either watch flag is enabled."""
    if self.args.watch_filesystem or self.args.watch_template:
      self.observer.start()

  def stop(self):
    """Stop watching and clean up."""
    self.observer.stop()
    self.observer.join()

  def on_modified(self, event):
    logging.info(f"{event.src_path} has been modified. Regenerating report...")
    generate_report(self.args)
    
    if self.args.serve:
      if self.server:
        self.server.shutdown()
        self.server.server_close()
      
      self.server_thread = threading.Thread(target=self._start_server)
      self.server_thread.daemon = True
      self.server_thread.start()


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
  parser.add_argument('--interval-seconds',
                      '-i',
                      help='Interval in seconds to generate report.',
                      type=int,
                      default=600)
  parser.add_argument('--watch-filesystem',
                      '-w',
                      help='Watch filesystem for changes and generate report.',
                      action='store_true')
  parser.add_argument('--watch-template',
                      '-t',
                      help='Watch the report templates for changes and generate report. For development purposes.',
                      action='store_true')

  return parser.parse_args()


def main():
    args = _parse_arguments()
    logging.getLogger().setLevel(os.environ.get('LOGLEVEL', 'INFO').upper())

    watcher = ReportWatcher(args)
    watcher.start()

    try:
        should_continue = args.serve or args.watch_filesystem or args.watch_template
        
        while should_continue:
            generate_report(args)
            # If interval is specified, wait and regenerate
            if args.interval_seconds > 0:
                time.sleep(args.interval_seconds)
            # If only watching filesystem and no interval, just wait
            else:
                time.sleep(1)
        else:
            generate_report(args)
            
    except KeyboardInterrupt:
        watcher.stop()
        logging.info('Exiting.')
        os._exit(0)


if __name__ == '__main__':
  logging.getLogger().setLevel(os.environ.get('LOGLEVEL', 'WARN').upper())
  main()
