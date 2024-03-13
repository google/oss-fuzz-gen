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
import logging
import os
import sys
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Dict, List

from google.cloud import storage

STORAGE_CLIENT = storage.Client()


class Benchmark:
  """The result directory of a benchmark."""

  def __init__(self, benchmark_dir: str) -> None:
    self.benchmark_dir = os.path.abspath(benchmark_dir)
    self.benchmark = os.path.basename(benchmark_dir).replace('output-', '', 1)

  @property
  def prompt(self) -> str:
    """Returns the prompt used by the benchmark."""
    prompt_path = os.path.join(self.benchmark_dir, 'prompt.txt')
    if not os.path.isfile(prompt_path):
      logging.warning('Prompt does not exist: %s', prompt_path)
      return ''
    with open(prompt_path) as prompt_file:
      return prompt_file.read()

  @property
  def targets(self) -> Dict[str, List[str]]:
    """Returns the generated targets of a benchmark in a directory, mapping
    the instance ID to a list of targets generated and fixed by LLM."""
    all_targets = {}
    raw_target_dir = os.path.join(self.benchmark_dir, 'raw_targets')
    if not os.path.isdir(raw_target_dir):
      logging.warning('Raw target dir does not exist: %s', raw_target_dir)
      return {}
    raw_targets = [
        instance for instance in os.listdir(raw_target_dir)
        if not instance.endswith('rawoutput')
    ]
    for instance in raw_targets:
      raw_target_path = os.path.join(raw_target_dir, instance)
      with open(raw_target_path) as target_file:
        all_targets[os.path.splitext(instance)[0]] = [target_file.read()]

    fixed_target_dir = os.path.join(self.benchmark_dir, 'fixed_targets')
    if not os.path.isdir(fixed_target_dir):
      logging.warning('Fixed target dir does not exist: %s', fixed_target_dir)
      return {}
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
      if not all_targets.get(instance):
        logging.warning('Benchmark instance does not exist: %s - %s',
                        self.benchmark_dir, instance)
        continue
      all_targets[instance].append(fixed_code)
    return all_targets

  @property
  def status(self) -> Dict[str, Dict[str, Any]]:
    """Returns the status of all instances of the benchmark, mapping the
    instance ID to its status JSON."""
    all_status = {}
    status_dir = os.path.join(self.benchmark_dir, 'status')
    if not os.path.isdir(status_dir):
      logging.warning('Status dir does not exist: %s', status_dir)
      return {}
    for instance in os.listdir(status_dir):
      status_json_path = os.path.join(status_dir, instance, 'result.json')
      if not os.path.isfile(status_json_path):
        logging.warning('Missing result JSON of benchmark instance: %s - %s',
                        self.benchmark, instance)
        continue
      with open(status_json_path) as file:
        try:
          all_status[instance] = json.load(file)
        except Exception as e:
          logging.warning(e)
          logging.warning(status_json_path)

    return all_status

  @property
  def is_valid_benchmark(self) -> bool:
    """Checks if this has a valid benchmark directory."""
    path = self.benchmark_dir
    expected_components = [
        'raw_targets', 'status', 'fixed_targets', 'prompt.txt'
    ]
    return all(
        os.path.exists(os.path.join(path, component))
        for component in expected_components)

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
    logging.info('Saved to: %s', data_filapath)


class Experiment:
  """The directory of an experiment, containing benchmark result directories."""

  def __init__(self, experiment_dir: str, bucket_uri: str = '') -> None:
    # The local result directory. The directory from bucket_uri will be
    # downloaded here if this directory does not contain experiment results.
    self.experiment = experiment_dir
    # The gcloud bucket result directory uri. It can be an empty string if
    # experiment_dir already contains experiment results.
    self.bucket_uri = bucket_uri
    self.benchmarks = []

    if bucket_url:
      _download_files(experiment_dir, bucket_url)
    for benchmark_dir in os.listdir(experiment_dir):
      benchmark_dir_path = os.path.join(experiment_dir, benchmark_dir)
      benchmark = Benchmark(benchmark_dir_path)
      if benchmark.is_valid_benchmark:
        self.benchmarks.append(benchmark)

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
    logging.info('Saved to: %s', data_filapath)


def _download_files(experiment_dir: str, bucket_url: str) -> None:
  """
  Downloads files in |bucket_url| to |experiment_dir| and preserve their paths.
  """
  bucket_name = bucket_url.removeprefix('gs://').split('/')[0]
  directory_prefix = bucket_url.removeprefix(f'gs://{bucket_name}/')
  bucket = STORAGE_CLIENT.bucket(bucket_name)
  blobs = bucket.list_blobs(prefix=directory_prefix)
  blobs_num = len(list(blobs))
  # Download blobs in parallel
  blobs = bucket.list_blobs(prefix=directory_prefix)
  with ThreadPoolExecutor(max_workers=40) as executor:
    for i, blob in enumerate(blobs):
      print(f'{i} / {blobs_num}')
      executor.submit(_download_file, blob, experiment_dir)


def _download_file(file_blob: storage.Blob, local_dir: str) -> None:
  """
  Downloads a file from |file_blob| and preserve its path after |bucket_dir|.
  """
  if not file_blob.name:
    logging.warning('Blob has no name: %s', file_blob)
    return
  if any(
      file_blob.name.endswith(suffix)
      for suffix in ['.rawoutput', '.log', 'log.txt']):
    return
  local_path = os.path.join(local_dir, file_blob.name)
  os.makedirs(os.path.dirname(local_path), exist_ok=True)
  file_blob.download_to_filename(local_path)


def _validate_bucket(directory_url: str) -> bool:
  """Checks if the |directory_url| is local or from a bucket."""
  # Assume we will only use gs:// links for simplicity in directory operations.
  return directory_url.startswith('gs://')


def _parse_args() -> argparse.Namespace:
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
  parser.add_argument('--experiment-bucket-dir-url',
                      '-u',
                      help="Path to the experiment result bucket directory.")
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

  if args.experiment_bucket_dir_url:
    assert _validate_bucket(args.experiment_bucket_dir_url), (
        f'{args.experiment_bucket_dir_url} is an invalid bucket directory URL.')
  if args.save_dir:
    os.makedirs(args.save_dir, exist_ok=True)
  return args


def main() -> int:
  """Main function to and initiate the parsing process."""
  args = _parse_args()
  if args.benchmark_dir:
    result = Benchmark(args.benchmark_dir)
    if not result.is_valid_benchmark:
      logging.info(
          'Invalid benchmark directory provided, missing necessary file.')
  elif args.experiment_dir:
    result = Experiment(args.experiment_dir, args.experiment_bucket_dir_url)
  else:
    return 1
  result.save_json(args.coverage, args.group, args.save_dir)
  return 0


if __name__ == "__main__":
  sys.exit(main())
