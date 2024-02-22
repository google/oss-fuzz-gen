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
"""Updates all yamls in target benchmark set to match with source.
Usage: python3 -m helper.update_comp_benchmarks.
Optional args:  [--source src_dir] [--target target_dir]
e.g.
python3 -m helper.update_comp_benchmarks \
--source benchmark-sets/all --target benchmark-sets/comparison"""
import argparse
import logging
import os

from experiment.benchmark import Benchmark

BENCHMARK_DIR = 'benchmark-sets'
SOURCE_SET = 'all'
TARGET_SET = 'comparison'


def parse_args() -> argparse.Namespace:
  """parse arguments"""
  parser = argparse.ArgumentParser(
      description=
      'Updates all benchmark yamls in <target> to match with <source>.')
  parser.add_argument(
      '-s',
      '--source',
      type=str,
      default=os.path.join(BENCHMARK_DIR, SOURCE_SET),
      help='The source benchmark set used to update target set.')
  parser.add_argument('-t',
                      '--target',
                      type=str,
                      default=os.path.join(BENCHMARK_DIR, TARGET_SET),
                      help='The target benchmark set to update.')

  args = parser.parse_args()
  assert os.path.isdir(args.target), '--target must be an existing directory.'
  assert os.path.isdir(args.source), '--source must be an existing directory.'

  return parser.parse_args()


def main():
  args = parse_args()
  target_path = args.target
  src_path = args.source

  for file_name in os.listdir(target_path):
    if not file_name.endswith('.yaml'):
      continue

    target_bms = Benchmark.from_yaml(os.path.join(target_path, file_name))
    try:
      source_bms = Benchmark.from_yaml(os.path.join(src_path, file_name))
    except FileNotFoundError:
      logging.error('%s is not found in %s', file_name, src_path)
      continue

    # Get raw name of the functions selected in target.
    functions = [b.function_name for b in target_bms]
    # Get the selected benchmarks from source.
    selected_bms = []
    for b in source_bms:
      if b.function_name in functions:
        selected_bms.append(b)

    Benchmark.to_yaml(selected_bms, target_path)
    logging.info('Updated %s', file_name)


if __name__ == '__main__':
  logging.basicConfig(level=logging.INFO)

  main()
