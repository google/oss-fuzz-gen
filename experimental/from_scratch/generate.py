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
from typing import Any, Optional, Tuple

# pyright: reportMissingImports = false
from fuzz_introspector import commands as fi_commands

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
  parser.add_argument('-t',
                      '--target-dir',
                      help='Directory with project source.',
                      required=True)
  parser.add_argument('-e',
                      '--language',
                      help='Main language of the target project source.',
                      required=True)
  parser.add_argument('--only-exact-match',
                      action='store_true',
                      help=('Flag to indicate if exact function name'
                            'matching is needed.'))
  parser.add_argument('-f',
                      '--function',
                      help='Name of function to generate a target for.',
                      default='')
  parser.add_argument('-s',
                      '--source-file',
                      help='Source file name to locate target function.',
                      default='')
  parser.add_argument('-sl',
                      '--source-line',
                      type=int,
                      help='Source line number to locate target function.',
                      default=0)

  return parser.parse_args()


def check_args(args) -> bool:
  """Check arguments."""
  if args.function and not args.source_file and not args.source_line:
    return True

  if not args.function and args.source_file and args.source_line:
    return True

  print('You must include either target function name by --function or target'
        'source file and line number by --source-file and --source-line')
  return False


def setup_model(args) -> models.LLM:
  return models.LLM.setup(ai_binary='',
                          name=args.model,
                          max_tokens=MAX_TOKENS,
                          num_samples=NUM_SAMPLES,
                          temperature=TEMPERATURE)


def find_function_by_name(all_functions, target_function_name,
                          only_exact_match):
  """Helper function to find the matching function."""
  for function in all_functions:
    if function.name == target_function_name:
      return function

  if not only_exact_match:
    for function in all_functions:
      if target_function_name in function.name:
        return function

  return None


def find_function_by_source_line(all_functions, target_source_file,
                                 target_source_line):
  """Helper function to find the matchin function by source
  file and source file."""
  for function in all_functions:
    source_file = function.parent_source.source_file
    if source_file.endswith(target_source_file):
      if function.start_line <= target_source_line <= function.end_line:
        return function

  return None


def get_target_benchmark(
    language, target_dir, target_function_name, only_exact_match,
    target_source_file, target_source_line
) -> Tuple[Optional[benchmarklib.Benchmark], Optional[dict[str, Any]]]:
  """Run introspector analysis on a target directory and extract benchmark"""
  if language in ['c', 'c++']:
    entrypoint = 'LLVMFuzzerTestOneInput'
  elif language == 'jvm':
    entrypoint = 'fuzzerTestOneInput'
  else:
    # Not supporting other language yet
    entrypoint = ''

  _, report = fi_commands.analyse_end_to_end(arg_language=language,
                                             target_dir=target_dir,
                                             entrypoint=entrypoint,
                                             out_dir='.',
                                             coverage_url='',
                                             report_name='report-name',
                                             module_only=True)
  project = report['light-project']

  # Trigger some analysis
  project.dump_module_logic(report_name='', dump_output=False)

  # Get target function
  if target_function_name:
    function = find_function_by_name(project.all_functions,
                                     target_function_name, only_exact_match)

  elif target_source_file and target_source_line > 0:
    function = find_function_by_source_line(project.all_functions,
                                            target_source_file,
                                            target_source_line)

  else:
    function = None

  if function:
    param_list = []

    for idx, arg_name in enumerate(function.arg_names):
      param_list.append({'name': arg_name, 'type': function.arg_types[idx]})

    # Build a context.
    function_source = function.function_source_code_as_text()
    xrefs = project.get_cross_references(function)
    if len(xrefs) > 10:
      xrefs = xrefs[:10]
    xref_strings = [xref.function_source_code_as_text() for xref in xrefs]

    context = {
        'func_source': function_source,
        'files': [],
        'decl': '',
        'xrefs': xref_strings,
        'header': '',
    }

    return benchmarklib.Benchmark(
        benchmark_id='sample',
        project='no-name',
        language=language,
        function_name=function.name,
        function_signature=function.sig,
        return_type=function.return_type,
        params=param_list,
        target_path=function.parent_source.source_file), context

  return None, None


def construct_fuzz_prompt(model, benchmark, context,
                          language) -> prompts.Prompt:
  """Local benchmarker"""
  if language in ['c', 'c++']:
    builder = prompt_builder.DefaultTemplateBuilder(model, benchmark=benchmark)
  else:
    builder = prompt_builder.DefaultJvmTemplateBuilder(model,
                                                       benchmark=benchmark)

  fuzz_prompt = builder.build([], project_context_content=context)
  return fuzz_prompt


def print_prompt(fuzz_prompt: prompts.Prompt) -> None:
  """Prints prompt to stdout."""
  print('Querying with the prompt')
  print('-' * 40)
  raw_prompt = fuzz_prompt.get()
  if isinstance(raw_prompt, list):
    for elem in raw_prompt:
      if isinstance(elem, dict) and 'content' in elem:
        print(elem['content'])
  else:
    print(raw_prompt)
  print('-' * 40)


def main():
  args = parse_args()
  model = setup_model(args)

  if not check_args(args):
    sys.exit(0)

  if args.language == 'c':
    language = 'c'
  elif args.language in ['c++', 'cpp']:
    language = 'c++'
  elif args.language in ['jvm', 'java']:
    language = 'jvm'
  else:
    print(f'Language {args.language} not support. Exiting.')
    sys.exit(0)

  target_benchmark, context = get_target_benchmark(language, args.target_dir,
                                                   args.function,
                                                   args.only_exact_match,
                                                   args.source_file,
                                                   args.source_line)

  if target_benchmark is None:

    print('Could not find target function. Exiting.')
    sys.exit(0)

  fuzz_prompt = construct_fuzz_prompt(model, target_benchmark, context,
                                      language)
  print_prompt(fuzz_prompt)
  os.makedirs(args.response_dir, exist_ok=True)
  print(f'Running query and writing results in {args.response_dir}')
  model.query_llm(fuzz_prompt, response_dir=args.response_dir)


if __name__ == "__main__":
  main()
