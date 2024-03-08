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
"""
This script provides functionality to parse benchmark data from a result
directory for training reward models.
It extracts the benchmark name, build rate, and line coverage difference
from the provided benchmark or experiment result directory.

Usage:
    python parse_training_data.py [-b <benchmark-dir>] [-e <experiment-dir>]
      [--coverage] [--group]
"""

import argparse
import json
import os
import sys
from typing import Any, Dict, List


class Benchmark:
  """The result directory of a benchmark."""

  def __init__(self, benchmark_dir: str) -> None:
    self.benchmark_dir = os.path.abspath(benchmark_dir)
    self.benchmark = os.path.basename(benchmark_dir).replace('output-', '', 1)

  @property
  def prompt(self) -> str:
    """Returns the prompt used by the benchmark."""
    prompt_path = os.path.join(self.benchmark_dir, 'prompt.txt')
    with open(prompt_path) as prompt_file:
      return prompt_file.read()

  @property
  def targets(self) -> Dict[str, List[str]]:
    """Returns the generated targets of a benchmark in a directory, mapping
    the instance ID to a list of targets generated and fixed by LLM."""
    all_targets = {}
    raw_target_dir = os.path.join(self.benchmark_dir, 'raw_targets')
    raw_targets = [
        instance for instance in os.listdir(raw_target_dir)
        if not instance.endswith('rawoutput')
    ]
    for instance in raw_targets:
      raw_target_path = os.path.join(raw_target_dir, instance)
      with open(raw_target_path) as target_file:
        all_targets[os.path.splitext(instance)[0]] = [target_file.read()]

    fixed_target_dir = os.path.join(self.benchmark_dir, 'fixed_targets')
    fix_dirs = [
        instance for instance in os.listdir(fixed_target_dir)
        if os.path.isdir(os.path.join(fixed_target_dir, instance))
    ]
    for fix_dir in sorted(fix_dirs):
      instance, _ = fix_dir.split('-F')
      code_path = [
          os.path.join(fixed_target_dir, fix_dir, f)
          for f in os.listdir(os.path.join(fixed_target_dir, fix_dir))
          if not (f == 'prompt.txt' and f.endswith('rawoutput'))
      ][0]
      with open(code_path) as code_file:
        fixed_code = code_file.read()
      all_targets[instance].append(fixed_code)
    return all_targets

  @property
  def status(self) -> Dict[str, Dict[str, Any]]:
    """Returns the status of all instances of the benchmark, mapping the
    instance ID to its status JSON."""
    all_status = {}
    status_dir = os.path.join(self.benchmark_dir, 'status')
    for instance in os.listdir(status_dir):
      status_json_path = os.path.join(status_dir, instance, 'result.json')
      if not os.path.isfile(status_json_path):
        print(f'Missing result JSON of {self.benchmark}')
        continue
      with open(status_json_path) as file:
        status = json.load(file)
        all_status[instance] = status
    return all_status

  @staticmethod
  def final_score(stat: Dict[str, Any], coverage: bool) -> float:
    """Evaluates the final score of a benchmark instance."""
    return stat.get('line_coverage_diff', 0.0) if coverage else float(
        stat.get('compiles', 0.0))

  def organize_group_pointwise(self,
                               coverage: bool = False
                              ) -> List[Dict[str, str | List[float]]]:
    """Organizes grouped pointwise training data for reward model."""
    data = []
    all_targets = self.targets
    prompt = self.prompt
    for instance, stat in self.status.items():
      targets = all_targets.get(instance, [])
      if not targets:
        continue
      scores = [0.0] * (len(targets) - 1) + [self.final_score(stat, coverage)]
      datum = {
          'prompt': prompt,
          'target': targets,
          'score': [scores],
      }
      data.append(datum)
    return data

  def organize_ungroup_pointwise(self,
                                 coverage: bool = False
                                ) -> List[Dict[str, str | float]]:
    """Organizes ungrouped pointwise training data for reward model."""
    data = []
    all_targets = self.targets
    prompt = self.prompt
    for instance, stat in self.status.items():
      targets = all_targets.get(instance, [])
      data.extend([{
          'prompt': prompt,
          'target': target,
          'score': 0.0
      } for target in targets[:-1]])
      data.append({
          'prompt': prompt,
          'target': targets[-1],
          'score': self.final_score(stat, coverage)
      })
    return data

  def organize_data(self, coverage: bool, group: bool) -> List[Dict[str, Any]]:
    """Organizes benchmark result into training data in the required format."""
    if group:
      return self.organize_group_pointwise(coverage)
    return self.organize_ungroup_pointwise(coverage)

  def save_json(self, coverage: bool, group: bool, save_dir: str):
    """Saves the training data into a JSON file."""
    data = self.organize_data(coverage, group)
    coverage_str = 'cov' if coverage else 'build'
    group_str = 'group' if group else 'ungroup'
    data_filename = (f'{self.benchmark}.{len(data)}.{coverage_str}.{group_str}'
                     f'.json')
    data_filapath = os.path.join(save_dir, data_filename)
    with open(data_filapath, 'w') as file:
      json.dump(data, file, indent=4)
    print(f'Saved to {data_filapath}.')


class Experiment:
  """The directory of an experiment, containing benchmark result directories."""

  def __init__(self, experiment_dir: str) -> None:
    self.experiment = experiment_dir
    self.benchmarks = []
    for benchmark_dir in os.listdir(experiment_dir):
      # Assumes all valid benchmark dir name starts with 'output-'.
      if not benchmark_dir.startswith('output-'):
        continue
      benchmark_dir_path = os.path.join(experiment_dir, benchmark_dir)
      self.benchmarks.append(Benchmark(benchmark_dir_path))

  def organize_data(self, coverage: bool, group: bool) -> List[Dict[str, Any]]:
    """Organizes experiment result into training data in the required format."""
    data = []
    for benchmark in self.benchmarks:
      data.extend(benchmark.organize_data(coverage, group))
    return data

  def save_json(self, coverage: bool, group: bool, save_dir: str) -> None:
    """Saves the training data into a JSON file."""
    data = self.organize_data(coverage, group)
    group_str = 'group' if group else 'ungroup'
    coverage_str = 'cov' if coverage else 'build'
    data_filename = (f'{self.experiment}.{len(data)}.{coverage_str}.{group_str}'
                     f'.json')
    data_filapath = os.path.join(save_dir, data_filename)
    with open(data_filapath, 'w') as file:
      json.dump(data, file, indent=4)
    print(f'Saved to {data_filapath}.')


def parse_args() -> argparse.Namespace:
  """Handles command-line arguments."""
  parser = argparse.ArgumentParser(
      description="Parse benchmark data from an HTML file.")
  parser.add_argument(
      '--coverage',
      '-c',
      action='store_true',
      help=('Use percentage code coverage instead of Boolean build status as '
            'benchmark score.'))
  parser.add_argument('--group',
                      '-g',
                      action='store_true',
                      help='Group targets by their prompt.')
  parser.add_argument('--benchmark-dir',
                      '-b',
                      type=str,
                      default='',
                      help="Path to the benchmark result directory.")
  parser.add_argument('--experiment-dir',
                      '-e',
                      type=str,
                      default='',
                      help="Path to the experiment result directory.")
  parser.add_argument('--save-dir',
                      '-s',
                      type=str,
                      default='',
                      help="Path to the directory for saving json result.")
  args = parser.parse_args()

  if args.benchmark_dir:
    args.benchmark_dir = args.benchmark_dir.rstrip('/')
  if args.experiment_dir:
    args.experiment_dir = args.experiment_dir.rstrip('/')

  assert bool(args.benchmark_dir) != bool(args.experiment_dir), (
      'Need exactly one directory of a benchmark or an experiment.')

  result_dir = args.benchmark_dir or args.experiment_dir
  assert os.path.isdir(result_dir), (
      f'{result_dir} needs to be an existing directory.')

  if args.save_dir:
    os.makedirs(args.save_dir, exist_ok=True)
  return args


def main() -> int:
  """Main function to and initiate the parsing process."""
  args = parse_args()
  if args.benchmark_dir:
    result = Benchmark(args.benchmark_dir)
  elif args.experiment_dir:
    result = Experiment(args.experiment_dir)
  else:
    return 1
  result.save_json(args.coverage, args.group, args.save_dir)
  return 0


if __name__ == "__main__":
  sys.exit(main())
