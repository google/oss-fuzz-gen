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
A script to generate LLM prompts based on existing example code and scaffold.
"""
import argparse
import sys

RAW_OUTPUT_EXT = '.rawoutput'


def is_raw_output(file: str) -> bool:
  """Checks if the |file| is a raw output from LLM by its extension."""
  return file.endswith(RAW_OUTPUT_EXT)


def parse_args() -> argparse.Namespace:
  """Parses command line arguments."""
  parser = argparse.ArgumentParser()
  parser.add_argument('-r',
                      '--llm-response-path',
                      type=str,
                      required=True,
                      help='A file containing the response from LLM.')
  parser.add_argument('-o',
                      '--output-path',
                      type=str,
                      required=True,
                      help='A directory to save the parsed output.')
  args = parser.parse_args()

  return args


def parse_code(response_path: str) -> str:
  """Parses the expected output from the |response_path|."""
  with open(response_path) as file:
    response = file.read()
  solution = response.split('</solution>')[0]
  solution = solution.replace('<code>', '').replace('</code>', '')

  lines = solution.splitlines()

  def should_remove(line):
    line = line.strip()
    return not line or line.startswith('```')

  # Remove leading empty lines or lines starting with ```.
  while lines and should_remove(lines[0]):
    lines.pop(0)
  # Remove trailing empty lines or lines starting with ```.
  while lines and should_remove(lines[-1]):
    lines.pop()

  return '\n'.join(lines)


def save_output(content: str, output_path: str) -> None:
  """Saves the parsed |content| to |output_path|."""
  with open(output_path, 'w+') as output_file:
    output_file.write(content)


def main():
  args = parse_args()
  content = parse_code(args.llm_response_path)
  save_output(content, args.output_path)


if __name__ == "__main__":
  sys.exit(main())
