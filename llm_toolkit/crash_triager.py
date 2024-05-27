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
"""Triaging the crash with LLM."""

import argparse
import os
import sys

from experiment import benchmark as benchmarklib
from llm_toolkit import models
from llm_toolkit import output_parser as parser
from llm_toolkit import prompt_builder


def parse_args():
  """Parses command line arguments."""
  argparser = argparse.ArgumentParser(description='Triage the crash with LLM.')
  argparser.add_argument(
      '-t',
      '--target-dir',
      type=str,
      default='./targets',
      help='The directory to store all fuzz targets to be triaged.')
  argparser.add_argument(
      '-o',
      '--intermediate-output-dir',
      type=str,
      default='./output',
      help=('The directory to store all intermediate output files (LLM prompt, '
            'rawoutput).'))
  argparser.add_argument('-p',
                         '--project',
                         type=str,
                         required=True,
                         help='The project name.')
  argparser.add_argument('-i',
                         '--crash-info',
                         type=str,
                         required=True,
                         help='The directory to store all crash information.')
  argparser.add_argument(
      '-c',
      '--code',
      type=str,
      required=True,
      help='The directory to store all crash-related code (project code).')

  args = argparser.parse_args()
  if args.target_dir and os.listdir(args.target_dir):
    assert os.path.isdir(
        args.target_dir
    ), f'--target-dir must take an existing directory: {args.target_dir}.'
    assert os.listdir(
        args.target_dir
    ), f'--target-dir must take a non-empty directory: {args.target_dir}.'

  os.makedirs(args.intermediate_output_dir, exist_ok=True)

  return args


def triage_all_crashes():
  """Reads crash information and relevant code, applies triage, \
        and saves the result."""
  # TODO(fdt622): Finish this.


# ========================= LLM Triage ========================= #


def llm_triage(
    ai_binary: str,
    target_path: str,
    benchmark: benchmarklib.Benchmark,
    crash_info: str,
    triage_model_name: str,
) -> None:
  """Triages crash with LLM based on crash information and relevant code."""
  with open(target_path) as target_file:
    target_code = target_file.read()

  response_dir = f'{os.path.splitext(target_path)[0]}-triage'
  os.makedirs(response_dir, exist_ok=True)
  prompt_path = os.path.join(response_dir, 'prompt.txt')

  apply_llm_triage(ai_binary,
                   benchmark,
                   target_code,
                   crash_info,
                   prompt_path,
                   response_dir,
                   triage_model_name,
                   temperature=0.5)

  triage_candidates = []
  for file in os.listdir(response_dir):
    if not parser.is_raw_output(file):
      continue
    triage_path = os.path.join(response_dir, file)
    triage = parser.parse_triage(triage_path)
    triage_candidates.append([triage_path, triage])

  if not triage_candidates:
    print(f'LLM did not generate rawoutput for {prompt_path}.')
    return

  # TODO(fdt622): Use the common vote
  # Currently, we prefer the longest triage.
  preferred_triage_path, preferred_triage = max(triage_candidates,
                                                key=lambda x: len(x[1]))
  print(
      f'Will use the longest triage: {os.path.relpath(preferred_triage_path)}.')
  preferred_triage_name, _ = os.path.splitext(preferred_triage_path)
  triage_report_path = os.path.join(response_dir,
                                    f'{preferred_triage_name}.txt')
  parser.save_output(preferred_triage, triage_report_path)


def apply_llm_triage(
    ai_binary: str,
    benchmark: benchmarklib.Benchmark,
    target_code: str,
    crash_info: str,
    prompt_path: str,
    response_dir: str,
    triage_model_name: str = models.DefaultModel.name,
    temperature: float = 0.4,
):
  """Queries LLM to triage the crash."""
  triage_model = models.LLM.setup(
      ai_binary=ai_binary,
      name=triage_model_name,
      num_samples=1,
      temperature=temperature,
  )

  builder = prompt_builder.DefaultTemplateBuilder(triage_model)
  # TODO(fdt622): go through and modify build_triage_prompt
  prompt = builder.build_triage_prompt(benchmark, target_code, crash_info)
  prompt.save(prompt_path)

  triage_model.generate_code(prompt, response_dir)


def main():
  #TODO(fdt622): Finish this.
  return 0


if __name__ == "__main__":
  sys.exit(main())
