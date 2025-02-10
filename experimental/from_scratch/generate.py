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
import logging
import os
import sys
from typing import Any, Optional, Tuple

# pyright: reportMissingImports = false
from fuzz_introspector import commands as fi_commands

from experiment import benchmark as benchmarklib
from llm_toolkit import models, prompt_builder, prompts

LOG_FMT = ('%(asctime)s.%(msecs)03d %(levelname)s '
           '%(module)s - %(funcName)s: %(message)s')

logging.basicConfig(
    level=logging.INFO,
    format=LOG_FMT,
    datefmt='%Y-%m-%d %H:%M:%S',
)
logger = logging.getLogger(name=__name__)

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
  parser.add_argument(
      '--far-reach',
      action='store_true',
      help='If set, will generate targets for all functions in far reach.')

  return parser.parse_args()


def check_args(args) -> bool:
  """Check arguments."""
  # Function name target
  if (args.function and not args.source_file and not args.source_line and
      not args.far_reach):
    return True

  # Source code location target
  if (not args.function and args.source_file and args.source_line and
      not args.far_reach):
    return True

  # Far-reach target.
  if (args.far_reach and not args.function and not args.source_file and
      not args.source_line):
    return True

  print(
      'You must include either:\n (1) target function name by --function;\n (2) target '
      'source file and line number by --source-file and --source-line;\n (3) '
      '--far-reach')
  return False


def setup_model(args) -> models.LLM:
  return models.LLM.setup(ai_binary='',
                          name=args.model,
                          max_tokens=MAX_TOKENS,
                          num_samples=NUM_SAMPLES,
                          temperature=TEMPERATURE)


def get_target_benchmark(
    language, target_dir, target_function_name, only_exact_match,
    target_source_file, target_source_line
) -> Tuple[Optional[benchmarklib.Benchmark], Optional[dict[str, Any]]]:
  """Run introspector analysis on a target directory and extract benchmark"""
  entrypoint = introspector_lang_to_entrypoint(language)

  _, report = fi_commands.analyse_end_to_end(arg_language=language,
                                             target_dir=target_dir,
                                             entrypoint=entrypoint,
                                             out_dir='.',
                                             coverage_url='',
                                             report_name='report-name',
                                             module_only=True,
                                             dump_files=False)
  project = report['light-project']
  introspector_project = report.get('introspector-project', None)
  if introspector_project:
    logger.info('Found introspector repoject')
    for analysis in introspector_project.optional_analyses:
      logger.info(analysis.name)
      if analysis.name == 'FarReachLowCoverageAnalyser':
        logger.info(analysis.get_json_string_result())
  else:
    logger.info('Did not find any introspector project')

  # Get target function
  if target_function_name:
    function = project.find_function_by_name(target_function_name,
                                             only_exact_match)

  elif target_source_file and target_source_line > 0:
    function = project.get_function_by_source_suffix_line(
        target_source_file, target_source_line)
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
  elif language == 'rust':
    builder = prompt_builder.DefaultRustTemplateBuilder(model,
                                                        benchmark=benchmark)
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


def get_fuzz_prompt_str(fuzz_prompt: prompts.Prompt) -> str:
  """Prints prompt to stdout."""
  prompt_string = ''
  raw_prompt = fuzz_prompt.get()
  if isinstance(raw_prompt, list):
    for elem in raw_prompt:
      if isinstance(elem, dict) and 'content' in elem:
        prompt_string += elem['content']
  return prompt_string


def introspector_lang_to_entrypoint(language: str) -> str:
  """Map an introspector language to entrypoint function."""
  if language in ['c', 'c++']:
    return 'LLVMFuzzerTestOneInput'
  elif language == 'jvm':
    return 'fuzzerTestOneInput'
  elif language == 'rust':
    return 'fuzz_target'
  else:
    # Not supporting other language yet
    return ''


def get_far_reach_benchmarks(
    language, target_dir
) -> list[Tuple[Optional[benchmarklib.Benchmark], Optional[dict[str, Any]]]]:
  """Run introspector analysis to extract fear-reaching targets and generate
  harnesses for it."""
  entrypoint = introspector_lang_to_entrypoint(language)

  _, report = fi_commands.analyse_end_to_end(arg_language=language,
                                             target_dir=target_dir,
                                             entrypoint=entrypoint,
                                             out_dir='.',
                                             coverage_url='',
                                             report_name='report-name',
                                             module_only=True,
                                             dump_files=False)
  project = report['light-project']
  introspector_project = report.get('introspector-project', None)
  result_dict = {}
  if introspector_project:
    logger.info('Found introspector repoject')
    for analysis in introspector_project.optional_analyses:
      if analysis.name == 'FarReachLowCoverageAnalyser':
        result_dict = analysis.json_results
  if not result_dict:
    logger.info('Found no analysis results from far-reach')
    sys.exit(0)

  target_benchmarks = []
  for target_function in result_dict.get('functions', []):
    # Get target function
    target_function_name = target_function['function_name']
    if target_function_name:
      function = project.find_function_by_name(target_function_name, True)
    else:
      function = None

    if function:
      param_list = []

      for idx, arg_name in enumerate(function.arg_names):
        param_list.append({'name': arg_name, 'type': function.arg_types[idx]})

      # Build a context.
      # Shorten the source function text if necessary.
      function_source = function.function_source_code_as_text()
      if len(function_source) > 1000:
        logger.info('Function source is %d bytes. Shortening to 1000',
                    len(function_source))
        function_source = function_source[:1000] + '\n ....'

      xrefs = project.get_cross_references(function)
      if len(xrefs) > 10:
        xrefs = xrefs[:10]
      xref_strings = []
      for xref in xrefs:
        source_str = xref.function_source_code_as_text()
        # Only include xref if it's not too large.
        if len(source_str) > 2000:
          continue
        xref_strings.append(source_str)

      context = {
          'func_source': function_source,
          'files': [],
          'decl': '',
          'xrefs': xref_strings,
          'header': '',
      }

      target_benchmarks.append((benchmarklib.Benchmark(
          benchmark_id='sample',
          project='no-name',
          language=language,
          function_name=function.name,
          function_signature=function.sig,
          return_type=function.return_type,
          params=param_list,
          target_path=function.parent_source.source_file), context))

  return target_benchmarks


def get_next_response_dir(response_dir: str) -> str:
  """Prepare next folder to put generate harness in."""
  idx = 0
  while True:
    target_response = os.path.join(response_dir, str(idx))
    if not os.path.isdir(target_response):
      return target_response
    idx += 1


def get_introspector_language(args) -> str:
  """Gets the language in introspector style from the CLI args."""
  if args.language == 'c':
    return 'c'
  elif args.language in ['c++', 'cpp']:
    return 'c++'
  elif args.language in ['jvm', 'java']:
    return 'jvm'
  elif args.language in ['rs', 'rust']:
    return 'rust'
  else:
    print(f'Language {args.language} not support. Exiting.')
    sys.exit(0)


def generate_far_reach_targets(args):
  """Generates a set of harnesses based on far-reach analysis."""
  model = setup_model(args)
  language = get_introspector_language(args)
  # Get the benchmarks corresponding to far-reach analysis.
  target_pairs = get_far_reach_benchmarks(language, args.target_dir)
  for target_benchmark, context in target_pairs:
    fuzz_prompt = construct_fuzz_prompt(model, target_benchmark, context,
                                        language)
    str_prompt = get_fuzz_prompt_str(fuzz_prompt)
    if len(str_prompt) > 15000:
      logger.info('Skipping prompt because its too large')
      print_prompt(fuzz_prompt)
      continue
    print_prompt(fuzz_prompt)
    response_dir = get_next_response_dir(args.response_dir)
    os.makedirs(response_dir, exist_ok=True)
    print(f'Running query and writing results in {response_dir}')
    try:
      model.query_llm(fuzz_prompt, response_dir=response_dir)
    except:
      pass


def generate_for_target_function(args):
  """Generate harness for single function/source location"""
  model = setup_model(args)
  language = get_introspector_language(args)
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


def main():
  """Entrypoint"""
  args = parse_args()
  if not check_args(args):
    sys.exit(0)

  if args.far_reach:
    generate_far_reach_targets(args)
  else:
    generate_for_target_function(args)


if __name__ == "__main__":
  main()
