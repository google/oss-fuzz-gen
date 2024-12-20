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
Search for benchmark results that contain a specific string.

Example usage:
To search for benchmarks that failed to parse error:
python3 -m helper.result_string_search -r results -s "<error>

</error>"

Optionally:
[--sub] provide subdirectory name to limit the scope of search.
[--url] provide template to output http links for easy access to web report.
"""
import argparse
import logging
import os
from typing import Optional


def _parse_args() -> argparse.Namespace:
  """Parses arguments."""
  parser = argparse.ArgumentParser(
      description=
      'Search for all benchmark that contains the <string> in <result>')
  parser.add_argument('-is',
                      '--include-strings',
                      type=str,
                      nargs='+',
                      default=[],
                      help='The string to include in result.')
  parser.add_argument('-es',
                      '--exclude-strings',
                      type=str,
                      nargs='+',
                      default=[],
                      help='The string to exclude in result.')
  parser.add_argument('-r',
                      '--result',
                      type=str,
                      required=True,
                      help='The root path to the result directory.')
  parser.add_argument(
      '-b',
      '--sub',
      type=str,
      default='',
      help=('The subdirectory to search in each output-* directories. '
            'Search in all subdirectories by default'))
  parser.add_argument(
      '-u',
      '--url',
      type=str,
      default='',
      help='Optional url template to web report for easy access.')

  args = parser.parse_args()
  assert os.path.isdir(args.result), '--result must be an existing directory.'

  output_dirs = os.listdir(args.result)
  assert any(
      os.path.isdir(os.path.join(args.result, d, args.sub)) for d in output_dirs
  ), ('--sub must be a directory in output-* directories under <result>\n'
      'E.g. fixed_targets, logs, raw_targets, status.')

  return args


def find_in_file(include_lines: list[str], exclude_lines: list[str],
                 file_path: str) -> bool:
  """Returns True if the file_path matches the in/exclude strings."""
  with open(file_path) as f:
    lines = f.readlines()

  for line in lines:
    if any(exclude_line in line for exclude_line in exclude_lines):
      return False

  for include_line in include_lines:
    if not any(include_line in line for line in lines):
      return False

  # logging.info('Matched in %s', file_path)
  return True


def find_in_dir(include_lines: list[str], exclude_lines: list[str],
                file_paths: list[str]) -> list[str]:
  """Returns files in |file_paths| that contain |include_lines|."""
  # Caveat: With support for multiline search in potentially large files
  # (e.g. log files), this function does not search for the exact substring
  # in the file containing the new line char. Instead, it returns True when:
  # other_text <search line 1> other_text
  # other_text <search line 2> other_text
  # can be found in the file.
  return [
      file_path for file_path in file_paths
      if find_in_file(include_lines, exclude_lines, file_path)
  ]


def main():
  args = _parse_args()
  result_dir = args.result
  include_lines = args.include_strings
  exclude_lines = args.exclude_strings
  sub = args.sub
  hits = []

  logging.info(
      'Search files including string:\n\t%s\nBut exclude string:\n\t%s\n',
      '\n\t'.join(include_lines), '\n\t'.join(exclude_lines))
  # Iterates through all output-*/
  for output_dir in sorted(os.listdir(result_dir)):
    if not os.path.isdir(os.path.join(result_dir, output_dir)):
      continue

    # Iterates through all subdirectories.
    for path, sub_dir, files in os.walk(
        os.path.join(result_dir, output_dir, sub)):
      # Except corpora.
      if 'corpora' in sub_dir:
        sub_dir.remove('corpora')

      # Iterates through all files in directory.
      if file_paths := find_in_dir(
          include_lines, exclude_lines,
          [os.path.join(path, file_name) for file_name in files]):
        hits.extend(file_paths)
        break

  hits.sort()
  url = args.url
  if url:
    benchmark_report = '\n'.join([f'{url}/{hit}' for hit in hits])
  else:
    benchmark_report = '\n'.join(hits)
  logging.info('Found Report URLs:')
  print(benchmark_report)


if __name__ == '__main__':
  logging.basicConfig(level=logging.INFO)
  main()
