#!/usr/bin/env python3
# Copyright 2025 Google LLC
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
"""Module for generating harnesses in arbitrary projects."""

import argparse
import os
import sys
from typing import Optional

# pyright: reportMissingImports = false
from fuzz_introspector.frontends import oss_fuzz as fi_oss_fuzz

from experiment import benchmark as benchmarklib
from llm_toolkit import models, prompt_builder, prompts

NUM_SAMPLES: int = 1
TEMPERATURE: float = 1
MAX_TOKENS: int = 8192


def parse_args() -> argparse.Namespace:
  """Parses command line arguments."""
  parser = argparse.ArgumentParser(
      description='Run all experiments that evaluates all target functions.')
  parser.add_argument('-l',
                      '--model',
                      default=models.DefaultModel.name,
                      help=('Models available: '
                            f'{", ".join(models.LLM.all_llm_names())}'))
  parser.add_argument('-r',
                      '--response-dir',
                      default='./responses',
                      help='LLM response directory.')
  parser.add_argument('-f',
                      '--function',
                      help='Name of function to generate a target for.',
                      required=True)
  parser.add_argument('-t',
                      '--target-dir',
                      help='Directory with project source.',
                      required=True)
  return parser.parse_args()


def setup_model(args) -> models.LLM:
  return models.LLM.setup(ai_binary='',
                          name=args.model,
                          max_tokens=MAX_TOKENS,
                          num_samples=NUM_SAMPLES,
                          temperature=TEMPERATURE)


def get_target_benchmark(
    language, target_dir,
    target_function_name) -> Optional[benchmarklib.Benchmark]:
  """Run introspector analysis on a target directory and extract benchmark"""
  project = fi_oss_fuzz.analyse_folder(language=language,
                                       directory=target_dir,
                                       dump_output=False)
  # Trigger some analysis
  project.dump_module_logic(report_name='', dump_output=False)

  for function in project.all_functions:
    if function.name == target_function_name:
      param_list = []
      for idx, arg_name in function.arg_names:
        param_list.append({'name': arg_name, 'type': function.arg_types[idx]})

      return benchmarklib.Benchmark(
          benchmark_id='sample',
          project='no-name',
          language=language,
          function_name=function.name,
          function_signature=function.sig,
          return_type=function.return_type,
          params=param_list,
          target_path=function.parent_source.source_file)
  return None


def construct_fuzz_prompt(model, benchmark) -> prompts.Prompt:
  """Local benchmarker"""
  builder = prompt_builder.DefaultTemplateBuilder(model, benchmark=benchmark)
  fuzz_prompt = builder.build([])
  return fuzz_prompt


def main():
  args = parse_args()
  model = setup_model(args)

  target_benchmark = get_target_benchmark('c++', args.target_dir, args.function)
  if target_benchmark is None:
    print('Could not find target function. Exiting.')
    sys.exit(0)

  fuzz_prompt = construct_fuzz_prompt(model, target_benchmark)
  os.makedirs(args.response_dir, exist_ok=True)
  print('Querying with the prompt')
  print('-' * 40)
  print(fuzz_prompt.get())
  print('-' * 40)
  print(f'Running query and writing results in {args.reponse_dir}')
  model.query_llm(fuzz_prompt, response_dir=args.response_dir)


if __name__ == "__main__":
  main()
