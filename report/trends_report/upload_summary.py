#!/usr/bin/env python
# Copyright 2025 Google LLC
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
"""Report generation tool to create summary json files for trends report."""

import argparse
import dataclasses
import json
import logging
import os
from typing import Any, Dict, List

from report.common import FileSystem, Results


@dataclasses.dataclass
class Summary:
  """Summary of the experiment for trends report."""
  benchmarks: List[Dict[str, Any]]
  accumulated_results: Dict[str, Any]
  projects: List[Dict[str, Any]]


def generate_summary(results_util: Results) -> Summary:
  """Returns a summary object from the experiment results."""
  benchmarks = []
  benchmark_summaries = []
  for benchmark_id in results_util.list_benchmark_ids():
    results, targets = results_util.get_results(benchmark_id)
    benchmark = results_util.match_benchmark(benchmark_id, results, targets)
    benchmarks.append(benchmark)
    benchmark_summaries.append({
        'id': benchmark.id,
        'project': benchmark.project,
        'function': benchmark.function,
        'signature': benchmark.signature,
        'build_success_rate': benchmark.result.build_success_rate,
        'crash_rate': benchmark.result.crash_rate,
        'found_bug': benchmark.result.found_bug,
        'max_coverage': benchmark.result.max_coverage,
        'max_line_coverage_diff': benchmark.result.max_line_coverage_diff,
    })

  accumulated_results = dataclasses.asdict(
      results_util.get_macro_insights(benchmarks))
  projects = list(
      map(dataclasses.asdict, results_util.get_project_summary(benchmarks)))
  return Summary(benchmark_summaries, accumulated_results, projects)


def _parse_arguments() -> argparse.Namespace:
  """Parses command line args."""
  parser = argparse.ArgumentParser(description=(
      'Report generation tool reads raw experiment output files and '
      'generates a summary json file used for trends report.'))

  parser.add_argument('--results-dir',
                      help='Directory with results from OSS-Fuzz-gen.',
                      required=True)
  parser.add_argument(
      '--output-path',
      help='Full path to store the summary json for trends report.',
      required=True)
  parser.add_argument('--date', help='Date of the experiment.', required=True)
  parser.add_argument('--name',
                      help='Name used for the benchmark results.',
                      required=True)
  parser.add_argument('--url',
                      help='Name used for the benchmark results.',
                      required=True)
  parser.add_argument('--benchmark-set',
                      help='Directory with benchmarks used for the experiment.',
                      required=True)
  parser.add_argument('--run-timeout',
                      help='Timeout the experiment uses for each fuzz test.',
                      required=True,
                      type=int)
  parser.add_argument(
      '--num-samples',
      help='Number of samples the experiment requests from the LLM.',
      required=True,
      type=int)
  parser.add_argument(
      '--llm-fix-limit',
      help='How many times the experiment asks the LLM to fix broken tests.',
      required=True,
      type=int)
  parser.add_argument('--model',
                      help='Model used for the experiment.',
                      required=True)
  parser.add_argument('--commit-hash',
                      help='Commit hash of the currect git checkout.',
                      required=True)
  parser.add_argument('--commit-date',
                      help='Commit date of the currect git checkout.',
                      required=True)
  parser.add_argument('--git-branch',
                      help='Git branch of the currect checkout.',
                      required=True)
  parser.add_argument('--tags',
                      help='Additional tags for this experiment.',
                      nargs="*",
                      type=str)

  return parser.parse_args()


def main():
  args = _parse_arguments()
  summary = dataclasses.asdict(
      generate_summary(
          Results(results_dir=args.results_dir,
                  benchmark_set=args.benchmark_set)))
  tags = [args.model, args.benchmark_set]
  if args.tags:
    tags.extend(args.tags)
  build_info = {
      'branch': args.git_branch,
      'commit_hash': args.commit_hash,
      'commit_date': args.commit_date,
  }
  summary_json = {
      'name': args.name,
      'date': args.date,
      'benchmark_set': args.benchmark_set,
      'llm_model': args.model,
      'url': args.url,
      'run_parameters': {
          'run_timeout': args.run_timeout,
          'num_samples': args.num_samples,
          'llm_fix_limit': args.llm_fix_limit,
      },
      'build_info': build_info,
      'tags': tags,
      **summary,
  }

  with FileSystem(args.output_path).open('w', encoding='utf-8') as f:
    json.dump(summary_json, f)


if __name__ == '__main__':
  logging.getLogger().setLevel(os.environ.get('LOGLEVEL', 'WARN').upper())
  main()
