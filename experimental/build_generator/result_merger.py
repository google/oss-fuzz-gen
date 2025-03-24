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
"""Merged projects created by from-scratch and OFG core."""

import argparse
import json
import logging
import os
import shutil
from typing import Any

logger = logging.getLogger(name=__name__)
LOG_FMT = ('%(asctime)s %(levelname)s [%(filename)s:%(lineno)d] '
           ': %(funcName)s: %(message)s')


def get_harness_name(raw_target_path: str, status_name: str) -> str:
  """Extracts harness path for the harness that builds for a given
  benchmark."""
  fuzzer_path = os.path.join(raw_target_path, status_name + '.cpp')
  if not os.path.isfile(fuzzer_path):
    fuzzer_path = os.path.join(raw_target_path, status_name + '.c')
    if not os.path.isfile(fuzzer_path):
      return ''
  return fuzzer_path


def extract_project_intrinsics(project_basename: str) -> tuple[str, str]:
  """Extracts project name and benchmark name from OFG result folder."""
  split_target = project_basename.split('-')
  target_project = '-'.join(split_target[1:-1])
  target_benchmark = split_target[-1]
  return target_project, target_benchmark


def get_path_to_benchmark_harness(benchmark_path: str, status_name: str) -> str:
  """Extracts the harness that builds for a given OFG core benchmark result."""
  fuzzer_path = get_harness_name(os.path.join(benchmark_path, 'fixed_targets'),
                                 status_name)
  if not fuzzer_path:
    fuzzer_path = get_harness_name(os.path.join(benchmark_path, 'raw_targets'),
                                   status_name)
  return fuzzer_path


def extract_top_project_of_benchmark(benchmark_path: str,
                                     project_path: str) -> dict:
  """Return top performing sample for a given benchmark result from OFG."""
  top_project = {}
  # Create folder names 01, 02, 03, ..., 11, 12... as named by OFG
  samples = [
      str(idx).zfill(2) for idx in range(1, 1 + len(os.listdir(benchmark_path)))
  ]
  for status_name in samples:
    result_json = os.path.join(benchmark_path, status_name, 'result.json')
    with open(result_json, 'r') as f:
      json_dict = json.load(f)
    fuzzer_path = get_path_to_benchmark_harness(project_path, status_name)

    if float(json_dict['coverage']) > 0.0:
      tmp_project = {
          'target': result_json,
          'result-stats': json_dict,
          'fuzzer_path': fuzzer_path,
      }
      if not top_project or top_project['result-stats'][
          'coverage'] < tmp_project['result-stats']['coverage']:
        top_project = tmp_project
  return top_project


def get_all_top_folders(target='results') -> list[dict[str, Any]]:
  """Returns paths of each top performing sample of an auto-gen benchmark."""
  targets_to_copy = []
  for project_basename in os.listdir(target):
    project_path = os.path.join(target, project_basename)

    # Extract the number of tries
    status_path = os.path.join(project_path, 'status')
    if not os.path.isdir(status_path):
      continue

    top_project = extract_top_project_of_benchmark(status_path, project_path)
    if not top_project:
      continue

    target_project, target_benchmark = extract_project_intrinsics(
        project_basename)
    top_project['project'] = target_project
    top_project['target_benchmark'] = target_benchmark
    targets_to_copy.append(top_project)
  return targets_to_copy


def copy_all_top_ofg_autogens(result_dir: str, destination: str) -> None:
  """Copies the best performing harness for each benchmark to the respective
  generated OSS-Fuzz project."""
  targets_to_copy = get_all_top_folders(result_dir)

  logger.info('Found %d targets to copy', len(targets_to_copy))
  for target in targets_to_copy:
    destination_path = os.path.join(destination, target['project'])
    logger.info('- copying: %s :: %s :: %s', target['project'],
                target['fuzzer_path'], destination_path)
    if not os.path.isdir(destination_path):
      logger.error('Destination project does not exist')
      continue

    fuzz_basename = os.path.basename(target['fuzzer_path'])
    dst_basename = f'fuzzer_{target["target_benchmark"]}_{fuzz_basename}'
    shutil.copy(target['fuzzer_path'],
                os.path.join(destination_path, dst_basename))


def parse_commandline():
  """Parse commandline."""
  parser = argparse.ArgumentParser()
  parser.add_argument('--result-dir',
                      '-r',
                      help='Results created by OFG.',
                      type=str)
  parser.add_argument(
      '--destination-dir',
      '-d',
      help='Folder with projects generated by from-scratch OFG.',
      type=str)
  return parser.parse_args()


def main():
  """CLI entrypoint."""
  logging.basicConfig(level=logging.INFO, format=LOG_FMT)

  args = parse_commandline()
  copy_all_top_ofg_autogens(args.result_dir, args.destination_dir)


if __name__ == "__main__":
  main()
