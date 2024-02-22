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
"""Updates all yamls in target benchmark set to match with source."""

import argparse
import os

from experiment.benchmark import Benchmark

BENCHMARK_DIR = 'benchmark-sets'
SOURCE_SET = 'all'
TARGET_SET = 'comparison'


def parse_args() -> argparse.Namespace:
  parser = argparse.ArgumentParser(
      description=
      'Updates all benchmark yamls in <target> to match with <source>.')
  parser.add_argument(
      '-s',
      '--source',
      type=str,
      default=SOURCE_SET,
      help='The source benchmark set used to update target set.')
  parser.add_argument('-t',
                      '--target',
                      type=str,
                      default=TARGET_SET,
                      help='The target benchmark set to update.')

  return parser.parse_args()


if __name__ == '__main__':
  # Usage: python3 -m helper.update_comp_benchmarks [--source src_dir] [--target target_dir].
  args = parse_args()
  target_path = os.path.join(BENCHMARK_DIR, args.target)
  src_path = os.path.join(BENCHMARK_DIR, args.source)

  for file_name in os.listdir(target_path):
    source_bms = Benchmark.from_yaml(os.path.join(src_path, file_name))
    target_bms = Benchmark.from_yaml(os.path.join(target_path, file_name))

    # Get raw name of the functions selected in target.
    functions = [b.function_name for b in target_bms]
    # Get the selected benchmarks from source.
    selected_bms = list(
        filter(lambda b: b.function_name in functions, source_bms))

    Benchmark.to_yaml(selected_bms, target_path)
    print('Updated', file_name)
