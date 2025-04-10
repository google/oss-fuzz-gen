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
from fuzz_introspector.analyses import (far_reach_low_coverage_analyser,
                                        test_analyser)

from experiment import benchmark as benchmarklib
from llm_toolkit import models, output_parser, prompt_builder, prompts

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


def _add_default_args(parser):
  """Default arguments for subparsers"""
  parser.add_argument('-m',
                      '--model',
                      default=models.DefaultModel.name,
                      help=('Models available: '
                            f'{", ".join(models.LLM.all_llm_names())}'))
  parser.add_argument('-o',
                      '--out-dir',
                      default='./results',
                      help='Directory where results will be stored.')
  parser.add_argument('-t',
                      '--target-dir',
                      help='Directory with project source.',
                      required=True)
  parser.add_argument('-l',
                      '--language',
                      help='Main language of the target project source.',
                      required=True)


def parse_args() -> argparse.Namespace:
  """Parses command line arguments."""
  parser = argparse.ArgumentParser(description='Fuzz generation helpers.')
  subparsers = parser.add_subparsers(dest='command')

  # Far reach generator
  far_reach_low_cov_generator = subparsers.add_parser(
      'generate-far-reach-targets',
      help='Generate fuzzing harnesses for far reaching functions')
  _add_default_args(far_reach_low_cov_generator)

  # Function specific generation
  function_target_generator = subparsers.add_parser(
      'generate-for-function',
      help='Generate fuzzing harness for specific function.')
  _add_default_args(function_target_generator)
  function_target_generator.add_argument('-f',
                                         '--function',
                                         help=('Function to target.'))
  function_target_generator.add_argument(
      '--only-exact-match',
      action='store_true',
      help=('Flag to indicate if exact function name'
            'matching is needed.'))

  # Source code location generator
  source_location_generator = subparsers.add_parser(
      'generate-for-source',
      help='Generate fuzzing harness for source code location')
  _add_default_args(source_location_generator)
  source_location_generator.add_argument(
      '-s',
      '--source-file',
      help='Source file name to locate target function.',
      default='')
  source_location_generator.add_argument(
      '-sl',
      '--source-line',
      type=int,
      help='Source line number to locate target function.',
      default=0)

  # Test to harness generator
  test_to_harness_all_generator = subparsers.add_parser(
      'generate-test-to-harness',
      help='Convert all tests in target to fuzz harnesses.')
  _add_default_args(test_to_harness_all_generator)

  return parser.parse_args()


def setup_model(args) -> models.LLM:
  return models.LLM.setup(ai_binary='',
                          name=args.model,
                          max_tokens=MAX_TOKENS,
                          num_samples=NUM_SAMPLES,
                          temperature=TEMPERATURE)


def get_target_benchmark_for_function(
    language, target_dir, target_function_name, only_exact_match
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
  function = project.find_function_by_name(target_function_name,
                                           only_exact_match)

  if function:
    param_list = []

    for idx, arg_name in enumerate(function.arg_names):
      param_list.append({'name': arg_name, 'type': function.arg_types[idx]})

    # Build a context.
    function_source = function.function_source_code_as_text()
    xrefs = project.get_cross_references_by_name(function.name)
    logger.info('Total xrefs found %d', len(xrefs))
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


def get_target_benchmark_for_source(
    language, target_dir, target_source_file, target_source_line
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
  function = project.get_function_by_source_suffix_line(target_source_file,
                                                        target_source_line)

  if function:
    param_list = []

    for idx, arg_name in enumerate(function.arg_names):
      param_list.append({'name': arg_name, 'type': function.arg_types[idx]})

    # Build a context.
    function_source = function.function_source_code_as_text()
    xrefs = project.get_cross_references_by_name(function.name)
    logger.info('Total xrefs found %d', len(xrefs))
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
  if language == 'jvm':
    return 'fuzzerTestOneInput'
  if language == 'rust':
    return 'fuzz_target'

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

  far_analysis = far_reach_low_coverage_analyser.FarReachLowCoverageAnalyser()
  far_analysis.standalone_analysis(introspector_project.proj_profile,
                                   introspector_project.profiles, '')

  target_benchmarks = []
  for target_function in far_analysis.json_results.get('functions', []):
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


def get_next_out_dir(out_dir: str) -> str:
  """Prepare next folder to put generate harness in."""
  idx = 0
  while True:
    target_response = out_dir + f'-{idx}'  #  os.path.join(out_dir, str(idx))
    if not os.path.isdir(target_response):
      return target_response
    idx += 1


def get_introspector_language(args) -> str:
  """Gets the language in introspector style from the CLI args."""
  if args.language == 'c':
    return 'c'
  if args.language in ['c++', 'cpp']:
    return 'c++'
  if args.language in ['jvm', 'java']:
    return 'jvm'
  if args.language in ['rs', 'rust']:
    return 'rust'

  print(f'Language {args.language} not support. Exiting.')
  sys.exit(0)


def generate_far_reach_targets(args):
  """Generates a set of harnesses based on far-reach analysis."""
  model = setup_model(args)
  language = get_introspector_language(args)
  # Get the benchmarks corresponding to far-reach analysis.
  target_pairs = get_far_reach_benchmarks(language, args.target_dir)
  fuzz_harnesses = []
  for target_benchmark, context in target_pairs:
    fuzz_prompt = construct_fuzz_prompt(model, target_benchmark, context,
                                        language)
    str_prompt = get_fuzz_prompt_str(fuzz_prompt)
    if len(str_prompt) > 15000:
      logger.info('Skipping prompt because its too large')
      print_prompt(fuzz_prompt)
      continue
    print_prompt(fuzz_prompt)

    try:
      fuzz_harness_response = model.ask_llm(fuzz_prompt)
      fuzz_harness_source = output_parser.filter_code(fuzz_harness_response)
      fuzz_harnesses.append(fuzz_harness_source)
    except Exception:  # pylint: disable=broad-exception-caught
      pass

  response_dir = get_next_out_dir(args.out_dir)
  os.makedirs(response_dir, exist_ok=True)
  extension = '.raw'
  if args.language == 'c++':
    extension = '.cpp'
  elif args.language == 'c':
    extension = '.c'
  for idx, fuzz_harness in enumerate(fuzz_harnesses):
    # adjust extension if needed
    if extension == '.cpp' and 'extern "C"' not in fuzz_harness:
      act_ext = '.c'
    else:
      act_ext = extension
    with open(os.path.join(response_dir, f'harness_{idx}{act_ext}'),
              'w',
              encoding='utf-8') as f:
      f.write(fuzz_harness)


def generate_test_to_harness_targets(args):
  """Test to harness converter"""
  model = setup_model(args)
  language = get_introspector_language(args)

  entrypoint = introspector_lang_to_entrypoint(args.language)

  _, report = fi_commands.analyse_end_to_end(arg_language=language,
                                             target_dir=args.target_dir,
                                             entrypoint=entrypoint,
                                             out_dir='.',
                                             coverage_url='',
                                             report_name='report-name',
                                             module_only=True,
                                             dump_files=False)
  introspector_project = report.get('introspector-project', None)

  tth_analysis = test_analyser.TestAnalyser()
  tth_analysis.standalone_analysis(introspector_project.proj_profile,
                                   introspector_project.profiles, '')
  tests = tth_analysis.test_file_paths
  for test_file_path in tests:
    benchmark = benchmarklib.Benchmark(benchmark_id='sample',
                                       project='no-name',
                                       language=language,
                                       function_name='',
                                       function_signature='',
                                       return_type='',
                                       params=[],
                                       target_path='',
                                       test_file_path=test_file_path)

    with open(test_file_path, 'r', encoding='utf-8') as f:
      test_source = f.read()

      # If the test source code is above a certain limit we'll reduce
      # the size of it to avoid having a too long token count.
      if len(test_source) > 5000:
        test_source = test_source[:2400] + '\n.....\n' + test_source[-2400:]
    builder = prompt_builder.TestToHarnessConverter(model, benchmark=benchmark)
    fuzz_prompt = builder.build([], test_source_code=test_source)

    try:
      raw_result = model.ask_llm(fuzz_prompt)
    except Exception:  # pylint: disable=broad-exception-caught
      continue

    logger.info('Filtering code')
    generated_source = output_parser.filter_code(raw_result)
    logger.info('Done filtering code')

    response_dir = get_next_out_dir(args.out_dir)
    os.makedirs(response_dir, exist_ok=True)
    with open(os.path.join(response_dir, 'fuzz.c'), 'w', encoding='utf-8') as f:
      f.write(generated_source)


def generate_for_target_function(args):
  """Generate harness for single function/source location"""
  model = setup_model(args)
  language = get_introspector_language(args)
  if args.command == 'generate-for-function':

    target_benchmark, context = get_target_benchmark_for_function(
        language, args.target_dir, args.function, args.only_exact_match)
  else:
    target_benchmark, context = get_target_benchmark_for_source(
        language, args.target_dir, args.source_file, args.source_line)

  if target_benchmark is None:
    print('Could not find target function. Exiting.')
    sys.exit(0)

  fuzz_prompt = construct_fuzz_prompt(model, target_benchmark, context,
                                      language)
  print_prompt(fuzz_prompt)
  os.makedirs(args.out_dir, exist_ok=True)
  print(f'Running query and writing results in {args.out_dir}')
  raw_response = model.ask_llm(fuzz_prompt)
  generated_fuzz_harness = output_parser.filter_code(raw_response)

  response_dir = get_next_out_dir(args.out_dir)
  os.makedirs(response_dir, exist_ok=True)
  extension = '.raw'
  if args.language == 'c++':
    extension = '.cpp'
  elif args.language == 'c':
    extension = '.c'

  if extension == '.cpp' and 'extern "C"' not in generated_fuzz_harness:
    act_ext = '.c'
  else:
    act_ext = extension

  with open(os.path.join(response_dir, f'harness{act_ext}'),
            'w',
            encoding='utf-8') as f:
    f.write(generated_fuzz_harness)


def main():
  """Entrypoint"""
  args = parse_args()

  if args.command == 'generate-far-reach-targets':
    generate_far_reach_targets(args)
  elif args.command == 'generate-test-to-harness':
    generate_test_to_harness_targets(args)
  else:
    generate_for_target_function(args)


if __name__ == "__main__":
  main()
