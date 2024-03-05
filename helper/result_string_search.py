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
Search for the benchmarks that contains a specific string in result.

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


def parse_args() -> argparse.Namespace:
  """parse arguments"""
  parser = argparse.ArgumentParser(
      description=
      'Search for all benchmark that contains the <string> in <result>')
  parser.add_argument('-s',
                      '--string',
                      type=str,
                      required=True,
                      help='The string to search in result.')
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

  output_dir = next(os.walk(args.result))[1][0]
  assert os.path.isdir(os.path.join(args.result, output_dir, args.sub)), (
      '--sub must be a directory in output-* directories under <result>:\n'
      'e.g. fixed_targets, logs, raw_targets, status.')

  if args.url:
    assert '[benchmark]' in args.url, (
        "--url must contain '[benchmark]'\n"
        "e.g. http://localhost:8080/benchmark/[benchmark]")

  return args


def find_in_dir(search_lines: list[str], file_paths: list[str]) -> bool:
  """Returns True if any file in |file_paths| contains |search_lines|."""
  # Caveat: With support for multiline search in potentially large files
  # (e.g. log files), this function does not search for the exact substring
  # in the file containing the new line char. Instead, it returns True when:
  # something <search line 1> something
  # some <search line 2> some
  # can be found in the file.
  for file_path in file_paths:
    with open(file_path) as f:
      count = 0
      for _, line in enumerate(f):
        if search_lines[count] in line:
          count += 1
          if count == len(search_lines):
            logging.info('Found in %s', file_path)
            return True
        else:
          count = 0

  return False


def main():
  args = parse_args()
  result_dir = args.result
  search_string = args.string
  sub = args.sub
  hits = []
  search_lines = search_string.split('\n')

  # Iterates through all output-*/
  for output_dir in next(os.walk(result_dir))[1]:

    # Iterates through all subdirectories.
    for path, sub_dir, files in os.walk(
        os.path.join(result_dir, output_dir, sub)):
      # Except corpora.
      if 'corpora' in sub_dir:
        sub_dir.remove('corpora')

      # Iterates through all files in directory.
      if find_in_dir(search_lines,
                     [os.path.join(path, file_name) for file_name in files]):
        hits.append(output_dir)
        break

  url = args.url
  if url:
    benchmark_report = '\n'.join(
        [url.replace('[benchmark]', hit) for hit in hits])
  else:
    benchmark_report = '\n'.join(hits)
  logging.info('Search string:\n%s\nwas found in:\n%s', search_string,
               benchmark_report)


if __name__ == '__main__':
  logging.basicConfig(level=logging.INFO)
  main()
