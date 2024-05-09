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


def _parse_code_block_by_marker(lines: list[str], start_marker: str,
                                end_marker: str) -> list[str]:
  """Parses code block lines based on markers."""
  block = []
  in_block = False

  for line in lines:
    if not in_block and start_marker in line:
      in_block = True
    elif in_block and end_marker in line:
      in_block = False
    elif in_block:
      block.append(line)
  return block if block else lines


def parse_code(response_path: str) -> str:
  """Parses the expected output from the |response_path|."""
  with open(response_path) as file:
    response = file.read()
  solution = response.split('</solution>')[0]
  lines = solution.splitlines()
  lines = _parse_code_block_by_marker(lines, '```', '```')
  lines = _parse_code_block_by_marker(lines, '<code>', '</code>')

  # Remove leading and trailing empty lines.
  while lines and not lines[0].strip():
    lines.pop(0)
  while lines and not lines[-1].strip():
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
