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
"""Auto OSS-Fuzz generator from inside OSS-Fuzz containers."""

import argparse
import json
import logging
import os
import shutil
import subprocess
from abc import abstractmethod
from typing import Any, Dict, List, Optional, Tuple, Type

import build_generator
import cxxfilt
import openai
import templates
import yaml

MAX_FUZZ_PER_HEURISTIC = 15
INTROSPECTOR_OSS_FUZZ_DIR = '/src/inspector'

INTROSPECTOR_ALL_FUNCTIONS_FILE = 'all-fuzz-introspector-functions.json'

LLM_MODEL = ''

FUZZER_PRE_HEADERS = '''#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
'''

logger = logging.getLogger(name=__name__)
LOG_FMT = ('%(asctime)s %(levelname)s [%(filename)s:%(lineno)d] '
           ': %(funcName)s: %(message)s')


def setup_model(model: str):
  global LLM_MODEL
  LLM_MODEL = model


def get_all_files_in_path(base_path: str,
                          path_to_subtract: Optional[str] = None) -> List[str]:
  """Gets all files in a tree and returns as a list of strings."""
  all_files = []
  if path_to_subtract is None:
    path_to_subtract = os.getcwd()
  for root, _, files in os.walk(base_path):
    for fi in files:
      path = os.path.join(root, fi)
      if path.startswith(path_to_subtract):
        path = path[len(path_to_subtract):]
      if len(path) > 0 and path[0] == '/':
        path = path[1:]
      all_files.append(path)
  return all_files


def determine_project_language(path: str) -> str:
  """Returns the likely language of a project by looking at file suffixes."""
  all_files = get_all_files_in_path(path, path)

  language_dict = {'c': 0, 'c++': 0}
  for source_file in all_files:
    if source_file.endswith('.c'):
      language_dict['c'] = language_dict['c'] + 1
    elif source_file.endswith('.cpp'):
      language_dict['c++'] = language_dict['c++'] + 1
    elif source_file.endswith('.cc'):
      language_dict['c++'] = language_dict['c++'] + 1

  target_language = 'c++'
  max_count = 0
  for language, count in language_dict.items():
    if count > max_count:
      target_language = language
      max_count = count
  return target_language


def get_all_functions_in_project(introspection_files_found):
  all_functions_in_project = []
  for fi_yaml_file in introspection_files_found:
    with open(fi_yaml_file, 'r') as file:
      yaml_content = yaml.safe_load(file)
    for elem in yaml_content['All functions']['Elements']:
      all_functions_in_project.append(elem)

  return all_functions_in_project


##################################################
#### Heuristics for auto generating harnesses ####
##################################################

GLOBAL_FUZZER_SOURCE_CACHE = {}


def get_source_from_cache(heuristic_name, target_func):
  funcs_in_cache = GLOBAL_FUZZER_SOURCE_CACHE.get(heuristic_name, [])
  if len(funcs_in_cache) == 0:
    return None
  for func, target_source in funcs_in_cache:
    if func['Func name'] == target_func['Func name']:
      return target_source
  return None


def add_to_source_cache(heuristic_name, target_func, fuzzer_source):
  funcs_in_cache = GLOBAL_FUZZER_SOURCE_CACHE.get(heuristic_name, [])
  funcs_in_cache.append((target_func, fuzzer_source))
  GLOBAL_FUZZER_SOURCE_CACHE[heuristic_name] = funcs_in_cache


class FuzzHeuristicGeneratorBase:
  """Base class for fuzzer heuristics generator."""
  language = ''
  name = ''

  def __init__(self, introspector_report: Dict[str, Any],
               all_header_files: List[str], test_dir):
    self.test_dir = test_dir
    self.all_header_files = all_header_files
    self.all_functions_in_project = []
    self.introspector_report = introspector_report
    self.github_url = ''

  @abstractmethod
  def get_fuzzer_intrinsics(self, func) -> Dict[str, Any]:
    """generates fuzzer source code, build and include directives."""

  @abstractmethod
  def get_fuzzing_targets(self) -> List[Any]:
    """Gets a list of possible function targets."""

  def log_prompt(self, prompt: str) -> None:
    """Logs the prompt to stdout."""
    prompt_out = f'{"-"*20} PROMPT {"-"*20}\n{prompt}\n{"-" * 48}'
    #prompt_out = '-' * 20 + ' PROMPT ' + '-' * 20 + '\n'
    #prompt_out += prompt + '\n'
    #prompt_out += '-' * 48
    logger.info(prompt_out)

  def get_header_intrinsics(self):
    """All header files and include directories."""
    headers_to_include = set()
    header_paths_to_include = set()
    for header_file in self.all_header_files:
      if '/test/' in header_file:
        continue
      if 'googletest' in header_file:
        continue
      headers_to_include.add(os.path.basename(header_file))
      header_paths_to_include.add('/'.join(header_file.split('/')[1:-1]))

    # Generate -I strings to be used in the build command.
    build_command_includes = ''
    for header_path_to_include in header_paths_to_include:
      build_command_includes += '-I' + os.path.join(
          self.test_dir, header_path_to_include) + ' '

    return headers_to_include, header_paths_to_include, build_command_includes

  def run_prompt_and_get_fuzzer_source(self, prompt):
    """Communicate to OpenAI prompt and extract harness source code."""

    if LLM_MODEL == 'openai':
      client = openai.OpenAI(api_key=os.getenv('OPENAI_API_KEY'))
      completion = client.chat.completions.create(model="gpt-3.5-turbo",
                                                  messages=[
                                                      {
                                                          'role': 'system',
                                                          'content': prompt
                                                      },
                                                  ])
      fuzzer_source = completion.choices[0].message.content
      if fuzzer_source is None:
        return ''
      fuzzer_source = fuzzer_source.replace('<code>', '').replace(
          '</code>', '').replace('```cpp', '').replace('```c',
                                                       '').replace('```', '')
    elif LLM_MODEL == 'vertex':
      logger.info('Using vertex')
      from vertexai.language_models import CodeGenerationModel
      parameters = {'temperature': 0.5, 'max_output_tokens': 512}
      code_generation_model = CodeGenerationModel.from_pretrained(
          'code-bison@001')
      response = code_generation_model.predict(prefix=prompt, **parameters)
      fuzzer_source = response.text.replace('<code>',
                                            '').replace('</code>',
                                                        '').replace('```', '')
    else:
      raise Exception(f'Did not find a relevant LLM for "{LLM_MODEL}".')

    logger.info('%s Source:', '>' * 45)
    logger.info(fuzzer_source)
    logger.info('-' * 65)
    return fuzzer_source

  def get_all_functions_sorted_by_cyclomatic_complexity(self) -> List[Any]:
    """Get functions from Fuzz Introspector sorted by cyclomatic complexity."""

    all_funcs = sorted(
        self.introspector_report['MergedProjectProfile']['all-functions'],
        key=lambda x: x['Accumulated cyclomatic complexity'],
        reverse=True)

    #for tdi in range(min(20, len(first_refined_functions_in_project))):
    uniqes = set()
    #idx = 0
    uniq_targets = []
    for func in all_funcs:
      if func['Func name'] in uniqes:
        continue
      if func['Func name'] == 'main':
        continue
      if len(func['Args']) == 0:
        continue
      uniqes.add(func['Func name'])
      uniq_targets.append(func)
      logger.info('Target: %s', func['Func name'])
      logger.info(' - Cyclomatic: %d',
                  func['Accumulated cyclomatic complexity'])

    return uniq_targets


def get_fuzzer_source_code(func: Dict[str, Any]) -> str:
  """Returns source code as string of a given introspector function."""
  source_file = func['Functions filename']
  src_begin_line = int(func['debug_function_info']['source']['source_line'])
  src_end_line = int(func['source_line_end'])

  with open(source_file, 'r') as f:
    file_content = f.read()
    split_lines = file_content.split('\n')
    source_code = '\n'.join(split_lines[src_begin_line - 1:src_end_line])
  return source_code


def get_cross_reference_functions(
    dst_func: Dict[str, Any],
    introspector_report: Dict[str, Any]) -> List[Dict[str, Any]]:
  """Returns the introspector functions that reference `dst_func`."""
  src_funcs = []
  for func in introspector_report['MergedProjectProfile']['all-functions']:
    if func['Func name'] == dst_func['Func name']:
      continue
    for callsite_dst in func['callsites']:
      if callsite_dst == dst_func['Func name']:
        src_funcs.append(func)
        break
  return src_funcs


class FuzzerGenHeuristic6(FuzzHeuristicGeneratorBase):
  """Heuristic that provides context around target function."""
  language = 'c'
  name = 'FuzzerGenHeuristic6'

  def __init__(self, introspector_report: Dict[str, Any],
               all_header_files: List[str], test_dir: str):
    super().__init__(introspector_report, all_header_files, test_dir)
    self.introspector_report = introspector_report
    self.all_header_files = all_header_files
    self.github_url = ''

  def get_fuzzing_targets(self) -> List[Any]:
    return self.get_all_functions_sorted_by_cyclomatic_complexity(
    )[:MAX_FUZZ_PER_HEURISTIC]

  def get_fuzzer_intrinsics(self, func: Dict[str, Any]) -> Dict[str, Any]:
    """Creates harness intrinsics, e.g. source code and build instructions."""
    (headers_to_include, _,
     build_command_includes) = self.get_header_intrinsics()

    type_constraints = 'the types of types function are:\n'
    for idx, arg in enumerate(func['debug_function_info']['args']):
      type_constraints += f'- Argument {idx+1} is of type `{arg}`\n'
    type_constraints += (
        'You must make sure the arguments passed to the ' +
        'function match the types of the function. Do this by casting ' +
        ' appropriately.')

    func_source_code = get_fuzzer_source_code(func)

    cross_references = get_cross_reference_functions(func,
                                                     self.introspector_report)
    cross_reference_text = ''
    if len(cross_references) > 0:
      # Add some source code samples
      max_crfs = 3
      for idx, cross_reference_func in enumerate(cross_references):
        if idx > max_crfs:
          break
        cross_reference_source = get_fuzzer_source_code(cross_reference_func)
        cross_reference_text += '\n'
        cross_reference_text += (
            'Example cross reference from function ' +
            f'{cross_reference_func["function_signature"]} and the source code '
            + 'of the function that calls into our target function is:\n')
        cross_reference_text += f'```c\n{cross_reference_source}\n```'

    if cross_reference_text:
      cross_reference_text = (
          'The target function is used by several other ' +
          'functions in the module. Use these as reference on how to call the '
          + 'target function correctly:\n' + cross_reference_text)

    logger.info('Sample targets:')
    prompt = f'''Hi, please write a fuzz harness for me.

The target project is {self.github_url} which is a open source project written in C. The harness you write should be in pure C as well.

I would like for you to write the harness targeting the function `{func["function_signature"]}.`

The source code for the function is: ```{func_source_code}```

The harness should be in libFuzzer style, with the code wrapped in `int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)`. Specifically, do not include `extern "C"` in the fuzzer code.

Please wrap all code in <code> tags and you should include nothing else but the code in your reply. Do not include any other text.

Make sure the ensure strings passed to the target are null-terminated.

There is one rule that your harness must satisfy: all of the header files in this library is {str(headers_to_include)}. Make sure to not include any header files not in this list.

Finally, {type_constraints}

The most important part of the harness is that it will build and compile correctly against the target code. Please focus on making the code as simple as possible in order to secure it can be build.

{cross_reference_text}
'''

    logger.info('%s%s%s', '-' * 45, f'\n{prompt}\n', '-' * 45)

    fuzzer_source = get_source_from_cache(self.name, func)
    if not fuzzer_source:
      fuzzer_source = self.run_prompt_and_get_fuzzer_source(prompt)
      comment_on_target = (f'// Heuristic: {self.name} :: Target: ' +
                           f'{func["Func name"]}\n')
      fuzzer_source = comment_on_target + FUZZER_PRE_HEADERS + fuzzer_source
      add_to_source_cache(self.name, func, fuzzer_source)
    else:
      logger.info('Using cached fuzzer source\n%s', fuzzer_source)

    fuzzer_target_call = func['Func name']
    fuzzer_intrinsics = {
        'full-source-code': fuzzer_source,
        'build-command-includes': build_command_includes,
        'autogen-id': f'{self.name}-{fuzzer_target_call}',
        'prompt': prompt
    }

    return fuzzer_intrinsics


class FuzzerGenHeuristic5(FuzzHeuristicGeneratorBase):
  """Heuristic that provides context around target function."""
  language = 'c'
  name = 'FuzzerGenHeuristic5'

  def __init__(self, introspector_report: Dict[str, Any],
               all_header_files: List[str], test_dir: str):
    super().__init__(introspector_report, all_header_files, test_dir)
    self.introspector_report = introspector_report
    self.all_header_files = all_header_files
    self.github_url = ''

  def get_fuzzing_targets(self) -> List[Any]:
    return self.get_all_functions_sorted_by_cyclomatic_complexity(
    )[:MAX_FUZZ_PER_HEURISTIC]

  def get_fuzzer_intrinsics(self, func) -> Dict[str, Any]:
    (headers_to_include, _,
     build_command_includes) = self.get_header_intrinsics()

    type_constraints = 'the types of types function are:\n'
    for idx, arg in enumerate(func['debug_function_info']['args']):
      type_constraints += f'- Argument {idx+1} is of type \"{arg}\"\n'
    type_constraints += (
        'You must make sure the arguments passed to the function match the ' +
        'types of the function. Do this by casting appropriately.')

    func_source_code = get_fuzzer_source_code(func)

    logger.info('Sample targets:')
    prompt = f'''Hi, please write a fuzz harness for me.

The target project is {self.github_url} which is a open source project written in C. The harness you write should be in pure C as well.

I would like for you to write the harness targeting the function `{func['function_signature']}`

The source code for the function is: ```{func_source_code}```

The harness should be in libFuzzer style, with the code wrapped in `int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)`. Specifically, do not include `extern "C"` in the fuzzer code.

Please wrap all code in <code> tags and you should include nothing else but the code in your reply. Do not include any other text.

Make sure the ensure strings passed to the target are null-terminated.

There is one rule that your harness must satisfy: all of the header files in this library is {headers_to_include}. Make sure to not include any header files not in this list.

Finally, {type_constraints}

The most important part of the harness is that it will build and compile correctly against the target code. Please focus on making the code as simple as possible in order to secure it can be build.
'''
    self.log_prompt(prompt)

    fuzzer_source = get_source_from_cache(self.name, func)
    if not fuzzer_source:
      fuzzer_source = self.run_prompt_and_get_fuzzer_source(prompt)
      comment_on_target = (f'// Heuristic: {self.name} :: Target: ' +
                           f'{func["Func name"]}\n')
      fuzzer_source = comment_on_target + FUZZER_PRE_HEADERS + fuzzer_source
      add_to_source_cache(self.name, func, fuzzer_source)
    else:
      logger.info('Using cached fuzzer source\n%s', fuzzer_source)

    fuzzer_target_call = func['Func name']
    fuzzer_intrinsics = {
        'full-source-code': fuzzer_source,
        'build-command-includes': build_command_includes,
        'autogen-id': f'{self.name}-{fuzzer_target_call}',
        'prompt': prompt
    }

    return fuzzer_intrinsics


class FuzzerGenHeuristic4(FuzzHeuristicGeneratorBase):
  """Simple LLM fuzz heuristic."""
  language = 'c'
  name = 'FuzzerGenHeuristic4'

  def __init__(self, introspector_report, all_header_files, test_dir):
    super().__init__(introspector_report, all_header_files, test_dir)
    self.introspector_report = introspector_report
    self.all_header_files = all_header_files
    self.github_url = ''

  def get_fuzzing_targets(self) -> List[Any]:
    return self.get_all_functions_sorted_by_cyclomatic_complexity(
    )[:MAX_FUZZ_PER_HEURISTIC]

  def get_fuzzer_intrinsics(self, func: Dict[str, Any]) -> Dict[str, Any]:
    (headers_to_include, _,
     build_command_includes) = self.get_header_intrinsics()

    type_constraints = 'the types of types function are:\n'
    for idx, arg in enumerate(func['debug_function_info']['args']):
      type_constraints += f'- Argument {idx+1} is of type \"{arg}\"\n'
    type_constraints += (
        'You must make sure the arguments passed to the function match the ' +
        'types of the function. Do this by casting appropriately.')

    logger.info('Sample targets:')
    prompt = f'''Hi, please write a fuzz harness for me.

The target project is {self.github_url} which is a open source project written in C. The harness you write should be in pure C as well.

I would like for you to write the harness targeting the function `{func['function_signature']}.`

The harness should be in libFuzzer style, with the code wrapped in `int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)`.

Please wrap all code in <code> tags and you should include nothing else but the code in your reply. Do not include any other text.

Make sure the ensure strings passed to the target are null-terminated.

There is one rule that your harness must satisfy: all of the header files in this library is {headers_to_include}. Make sure to not include any header files not in this list.

Finally, {type_constraints}

The most important part of the harness is that it will build and compile correctly against the target code. Please focus on making the code as simple as possible in order to secure it can be build.
'''
    self.log_prompt(prompt)

    fuzzer_source = get_source_from_cache(self.name, func)
    if not fuzzer_source:
      fuzzer_source = self.run_prompt_and_get_fuzzer_source(prompt)
      comment_on_target = (f'// Heuristic: {self.name} :: Target: ' +
                           f'{func["Func name"]}\n')
      fuzzer_source = comment_on_target + FUZZER_PRE_HEADERS + fuzzer_source

      add_to_source_cache(self.name, func, fuzzer_source)
    else:
      logger.info('Using cached fuzzer source\n%s', fuzzer_source)

    fuzzer_target_call = func['Func name']
    fuzzer_intrinsics = {
        'full-source-code': fuzzer_source,
        'build-command-includes': build_command_includes,
        'autogen-id': f'{self.name}-{fuzzer_target_call}',
        'prompt': prompt
    }

    return fuzzer_intrinsics


class FuzzerGenHeuristic1(FuzzHeuristicGeneratorBase):
  """Simple LLM fuzz heuristic."""
  language = 'c'
  name = 'FuzzerGenHeuristic1'

  def __init__(self, introspector_report, all_header_files, test_dir):
    super().__init__(introspector_report, all_header_files, test_dir)
    self.introspector_report = introspector_report
    self.all_header_files = all_header_files
    self.github_url = ''

  def get_fuzzing_targets(self) -> List[Any]:
    return self.get_all_functions_sorted_by_cyclomatic_complexity(
    )[:MAX_FUZZ_PER_HEURISTIC]

  def get_fuzzer_intrinsics(self, func: Dict[str, Any]) -> Dict[str, Any]:
    headers_to_include, _, build_command_includes = self.get_header_intrinsics()

    type_constraints = 'the types of types function are:\n'
    for idx, arg in enumerate(func['debug_function_info']['args']):
      type_constraints += f'- Argument {idx+1} is of type \"{arg}\"\n'
    type_constraints += (
        'You must make sure the arguments passed to the function match the ' +
        'types of the function. Do this by casting appropriately.')

    logger.info('Sample targets:')
    prompt = f'''Hi, please write a fuzz harness for me.

The target project is {self.github_url} which is a open source project written in C. The harness you write should be in pure C as well.

I would like for you to write the harness targeting the function `{func['function_signature']}`

The harness should be in libFuzzer style, with the code wrapped in LLVMFuzzerTestOneInput.

Please wrap all code in <code> tags and you should include nothing else but the code in your reply. Do not include any other text.

Make sure the ensure strings passed to the target are null-terminated.

There is one rule that your harness must satisfy: all of the header files in this library is {str(headers_to_include)}. Make sure to not include any header files not in this list.

Finally, {type_constraints}
'''

    fuzzer_source = get_source_from_cache(self.name, func)
    if not fuzzer_source:
      fuzzer_source = self.run_prompt_and_get_fuzzer_source(prompt)
      comment_on_target = (f'// Heuristic: {self.name} :: Target: '
                           f'{func["Func name"]}\n')
      fuzzer_source = comment_on_target + FUZZER_PRE_HEADERS + fuzzer_source
      add_to_source_cache(self.name, func, fuzzer_source)
    else:
      logger.info('Using cached fuzzer source\n%s', fuzzer_source)

    fuzzer_target_call = func['Func name']
    fuzzer_intrinsics = {
        'full-source-code': fuzzer_source,
        'build-command-includes': build_command_includes,
        'autogen-id': f'{self.name}-{fuzzer_target_call}',
        'prompt': prompt
    }

    return fuzzer_intrinsics


class FuzzerGenHeuristic2(FuzzHeuristicGeneratorBase):
  """Simple LLM fuzz heuristic."""
  language = 'c++'
  name = 'FuzzerGenHeuristic2'

  def __init__(self, introspector_report, all_header_files, test_dir):
    super().__init__(introspector_report, all_header_files, test_dir)
    self.introspector_report = introspector_report
    self.all_header_files = all_header_files
    self.github_url = ''

  def get_fuzzing_targets(self) -> List[Any]:
    return self.get_all_functions_sorted_by_cyclomatic_complexity(
    )[:MAX_FUZZ_PER_HEURISTIC]

  def get_fuzzer_intrinsics(self, func: Dict[str, Any]) -> Dict[str, Any]:
    headers_to_include, _, build_command_includes = self.get_header_intrinsics()
    type_constraints = 'the types of types function are:\n'
    for idx, arg in enumerate(func['debug_function_info']['args']):
      type_constraints += f'- Argument {idx+1} is of type \"{arg}\"\n'
    type_constraints += (
        'You must make sure the arguments passed to the function match the ' +
        'types of the function. Do this by casting appropriately.')

    logger.info('Sample targets:')
    prompt = f'''Hi, please write a fuzz harness for me.

The target project is {self.github_url} which is a open source project written in CPP.

I would like for you to write the harness targeting the function `{func['function_signature']}`.

The harness should be in libFuzzer style, with the code wrapped in LLVMFuzzerTestOneInput.

Please wrap all code in <code> tags and you should include nothing else but the code in your reply. Do not include any other text.

Make sure the ensure strings passed to the target are null-terminated.

There are two rules that your harness must satisfy: First, all of the header files in this library is {str(headers_to_include)}. Make sure to not include any header files not in this list. Second, you must wrap the harness such that it catches all exceptions (use "...") thrown by the target code.

Finally, {type_constraints}
'''

    fuzzer_source = get_source_from_cache(self.name, func)
    if not fuzzer_source:
      fuzzer_source = self.run_prompt_and_get_fuzzer_source(prompt)
      comment_on_target = (f'// Heuristic: {self.name} :: Target: ' +
                           f'{func["Func name"]}\n')
      fuzzer_source = comment_on_target + FUZZER_PRE_HEADERS + fuzzer_source
      add_to_source_cache(self.name, func, fuzzer_source)
    else:
      logger.info('Using cached fuzzer source\n%s', fuzzer_source)

    fuzzer_target_call = func['Func name']
    fuzzer_intrinsics = {
        'full-source-code': fuzzer_source,
        'build-command-includes': build_command_includes,
        'autogen-id': f'{self.name}-{fuzzer_target_call}',
        'prompt': prompt
    }

    return fuzzer_intrinsics


class FuzzerGenHeuristic3(FuzzHeuristicGeneratorBase):
  """Simple LLM fuzz heuristic."""
  language = 'c++'
  name = 'FuzzerGenHeuristic3'

  def __init__(self, introspector_report, all_header_files, test_dir):
    super().__init__(introspector_report, all_header_files, test_dir)
    self.introspector_report = introspector_report
    self.all_header_files = all_header_files
    self.github_url = ''

  def get_fuzzing_targets(self) -> List[Any]:
    """Target selector."""
    return self.get_all_functions_sorted_by_cyclomatic_complexity(
    )[:MAX_FUZZ_PER_HEURISTIC]

  def get_fuzzer_intrinsics(self, func: Dict[str, Any]) -> Dict[str, Any]:
    """Harness generator."""
    headers_to_include, _, build_command_includes = self.get_header_intrinsics()

    type_constraints = 'the types of types function are:\n'
    for idx, arg in enumerate(func['debug_function_info']['args']):
      type_constraints += f'- Argument {idx+1} is of type \"{arg}\"\n'
      type_constraints += (
          'You must make sure the arguments passed to the function match the ' +
          'types of the function. Do this by casting appropriately.')

    prompt = f'''Hi, please write a fuzz harness for me.

The target project is {self.github_url} which is a open source project written in CPP.

I would like for you to write the harness targeting the function `{func['function_signature']}`.

The harness should be in libFuzzer style, with the code wrapped in LLVMFuzzerTestOneInput.

Please wrap all code in <code> tags and you should include nothing else but the code in your reply. Do not include any other text.

Make sure the ensure strings passed to the target are null-terminated.

In terms of types of the target function, {type_constraints}

There are rules that your harness must satisfy:
1) All of the header files in this library is {str(headers_to_include)}. Make sure to not include any header files not in this list and only include the ones relevant for the target function.
2) You must wrap the harness such that it catches all exceptions (use "...") thrown by the target code.

'''

    fuzzer_source = get_source_from_cache(self.name, func)
    if not fuzzer_source:
      fuzzer_source = self.run_prompt_and_get_fuzzer_source(prompt)
      comment_on_target = (f'// Heuristic: {self.name} :: Target: ' +
                           f'{func["Func name"]}\n')
      fuzzer_source = comment_on_target + FUZZER_PRE_HEADERS + fuzzer_source
      add_to_source_cache(self.name, func, fuzzer_source)
    else:
      logger.info('Using cached fuzzer source\n%s', fuzzer_source)

    fuzzer_target_call = func['Func name']
    fuzzer_intrinsics = {
        'full-source-code': fuzzer_source,
        'build-command-includes': build_command_includes,
        'autogen-id': f'{self.name}-{fuzzer_target_call}',
        'prompt': prompt,
    }

    return fuzzer_intrinsics


def refine_and_filter_introspector_functions(all_functions_in_project):
  """Converts raw list of fuzz introspector functions to a refined list."""
  first_refined_functions_in_project = []
  for func in all_functions_in_project:
    to_cont = True
    try:
      demangled = cxxfilt.demangle(func['functionName'])
    except:
      demangled = func['functionName']

    discarded_function_names = {'cxx_global_var_init'}
    for funcname in discarded_function_names:
      if funcname in demangled:
        to_cont = False
        break

    src_file = func['functionSourceFile']
    if src_file.strip() == '':
      continue
    discarded_paths = {
        'googletest',
        'usr/local/bin',
    }

    for discarded_path in discarded_paths:
      if discarded_path in src_file:
        to_cont = False
        break

    # Exit if we need to.
    if not to_cont:
      continue

    func['Func name'] = demangled
    first_refined_functions_in_project.append(func)
  return first_refined_functions_in_project


def get_all_header_files(all_files: List[str]) -> List[str]:
  all_header_files = []
  for yaml_file in all_files:
    if yaml_file.endswith('.h'):
      all_header_files.append(yaml_file)
  return all_header_files


def get_all_introspector_files(target_dir):
  all_files = get_all_files_in_path(target_dir)
  introspection_files_found = []
  for yaml_file in all_files:
    if 'allFunctionsWithMain' in yaml_file:
      #print(yaml_file)
      introspection_files_found.append(yaml_file)
    elif 'fuzzerLogFile-' in yaml_file and yaml_file.endswith('.yaml'):
      introspection_files_found.append(yaml_file)
  return introspection_files_found


def build_empty_fuzzers(build_workers, language):
  """Run build scripts against an empty fuzzer harness."""
  # Stage 2: perform program analysis to extract data to be used for
  # harness generation.

  # For each of the auto generated build scripts try to link
  # the resulting static libraries against an empty fuzzer.
  fuzz_compiler, _, empty_fuzzer_file, fuzz_template = get_language_defaults(
      language)
  for test_dir, build_worker in build_workers.items():
    logger.info('Test dir: %s :: %s', test_dir,
                str(build_worker.executable_files_build['refined-static-libs']))

    if not build_worker.executable_files_build['refined-static-libs']:
      continue

    logger.info('Trying to link in an empty fuzzer')

    #empty_fuzzer_file = '/src/empty-fuzzer.cpp'
    with open(empty_fuzzer_file, 'w') as f:
      f.write(fuzz_template)

    # Try to link the fuzzer to the static libs
    cmd = [
        fuzz_compiler, '-fsanitize=fuzzer', '-fsanitize=address',
        empty_fuzzer_file
    ]
    for refined_static_lib in build_worker.executable_files_build[
        'refined-static-libs']:
      cmd.append(os.path.join(test_dir, refined_static_lib))

    logger.info('Command [%s]', ' '.join(cmd))
    try:
      subprocess.check_call(' '.join(cmd), shell=True)
      base_fuzz_build = True
    except subprocess.CalledProcessError:
      base_fuzz_build = False

    logger.info('Base fuzz build: %s', str(base_fuzz_build))
    build_worker.base_fuzz_build = base_fuzz_build


def refine_static_libs(build_results) -> None:
  """Returns a list of static libraries with substitution of common gtest
  libraries, which should not be linked in the fuzzer builds."""
  for test_dir in build_results:
    refined_static_list = []
    libs_to_avoid = {
        'libgtest.a', 'libgmock.a', 'libgmock_main.a', 'libgtest_main.a'
    }
    build_worker = build_results[test_dir]
    static_libs = build_worker.executable_files_build['static-libs']
    for static_lib in static_libs:
      if any(
          os.path.basename(static_lib) in lib_to_avoid
          for lib_to_avoid in libs_to_avoid):
        continue
      refined_static_list.append(static_lib)
    build_worker.executable_files_build[
        'refined-static-libs'] = refined_static_list


def get_language_defaults(language: str):
  compilers_and_flags = {
      'c': ('$CC', '$CFLAGS', '/src/empty-fuzzer.c', templates.C_BASE_TEMPLATE),
      'c++': ('$CXX', '$CXXFLAGS', '/src/empty-fuzzer.cpp',
              templates.CPP_BASE_TEMPLATE),
  }
  return compilers_and_flags[language]


def run_introspector_on_dir(build_worker, test_dir,
                            language) -> Tuple[bool, List[str]]:
  """Runs Fuzz Introspector on a target directory with the ability
    to analyse code without having fuzzers (FUZZ_INTROSPECTOR_AUTO_FUZZ=1).

    This is done by running the bbuild script that succeeded using introspector
    sanitizer from OSS-Fuzz, where introspector will collect data form any
    executable linked during the vanilla build.

    This is done by way of the OSS-Fuzz `compile` command and by setting
    the environment appropriately before running this command.
    """
  introspector_vanilla_build_script = build_worker.build_script
  (fuzz_compiler, fuzz_flags, empty_fuzzer_file,
   fuzz_template) = get_language_defaults(language)

  with open(empty_fuzzer_file, 'w') as f:
    f.write(fuzz_template)

  # Try to link the fuzzer to the static libs
  fuzzer_build_cmd = [
      fuzz_compiler, fuzz_flags, '$LIB_FUZZING_ENGINE', empty_fuzzer_file
  ]
  for refined_static_lib in build_worker.executable_files_build[
      'refined-static-libs']:
    fuzzer_build_cmd.append('-Wl,--whole-archive')
    fuzzer_build_cmd.append(os.path.join(test_dir, refined_static_lib))

  fuzzer_build_cmd.append('-Wl,--allow-multiple-definition')
  introspector_vanilla_build_script += '\n'
  introspector_vanilla_build_script += ' '.join(fuzzer_build_cmd)

  with open('/src/build.sh', 'w') as bs:
    bs.write(introspector_vanilla_build_script)

  modified_env = os.environ
  modified_env['SANITIZER'] = 'introspector'
  modified_env['FUZZ_INTROSPECTOR_AUTO_FUZZ'] = '1'
  modified_env['PROJECT_NAME'] = 'auto-fuzz-proj'
  modified_env['FUZZINTRO_OUTDIR'] = test_dir
  try:
    subprocess.check_call('compile',
                          shell=True,
                          env=modified_env,
                          stdout=subprocess.DEVNULL,
                          stderr=subprocess.DEVNULL)
    build_returned_error = False
  except subprocess.CalledProcessError:
    build_returned_error = True
  logger.info('Introspector build: %s', str(build_returned_error))
  return build_returned_error, fuzzer_build_cmd


def log_fuzzer_source(full_fuzzer_source: str):
  harness_source_out = (
      f'{"-" * 20} HARNESS SOURCE {"-" * 20}\n{full_fuzzer_source}\n{"-" * 56}')
  logger.info(harness_source_out)


def generate_harness_intrinsics(
    heuristic: FuzzHeuristicGeneratorBase,
    results,
    language: str,
    test_dir: str,
    fuzzer_build_cmd: List[str],
    verbose_logging: bool = True) -> List[Dict[str, Any]]:
  """Get fuzzer source code, build script and misc for each heuristic."""
  # TODO (david): add oss-fuzz-gen ore prompt generation logic.

  # Get list of target functions for the heuristic.
  fuzzer_targets = heuristic.get_fuzzing_targets()
  logger.info('Found %d fuzzer targets', len(fuzzer_targets))

  # For each target function do:
  # 1) Use the heuristic to generate intrinsics:
  #    - Fuzzer source code
  #    - Include folders for the build script
  # 2) Create the build command needed for the fuzzer, by extending
  #    `fuzzer_build_cmd`
  # 3) Wrap the above in a dictionary and append to results list.
  _, _, fuzzer_target_file, _ = get_language_defaults(language)
  harness_builds_to_validate = []
  for fuzz_target in fuzzer_targets:
    # Get intrinsics for the target function.
    fuzzer_intrinsics = heuristic.get_fuzzer_intrinsics(fuzz_target)
    if fuzzer_intrinsics is None:
      continue

    if verbose_logging:
      logger.info('[+] Fuzzer generated:')
      logger.info('- Fuzz generator id: %s',
                  str(fuzzer_intrinsics["autogen-id"]))
      logger.info('- Build cmd includes %s',
                  str(fuzzer_intrinsics["build-command-includes"]))
      logger.info('- Source code:')
      log_fuzzer_source(fuzzer_intrinsics['full-source-code'])

    # Generate a build script for compiling the fuzzer with ASAN.
    final_asan_build_script = results[test_dir].build_script + '\n'
    fuzzer_out = '/src/generated-fuzzer'
    fuzz_cmd = ' '.join(fuzzer_build_cmd) + ' '
    fuzz_includes = fuzzer_intrinsics["build-command-includes"]
    final_asan_build_script += f'{fuzz_cmd} {fuzz_includes} -o {fuzzer_out}'

    # Wrap all parts we need for building and running the fuzzer.
    harness_builds_to_validate.append({
        'build-script': final_asan_build_script,
        'source': fuzzer_intrinsics['full-source-code'],
        'fuzzer-file': fuzzer_target_file,
        'fuzzer-out': fuzzer_out,
        'fuzzer-intrinsics': fuzzer_intrinsics,
    })
  return harness_builds_to_validate


def evaluate_heuristic(test_dir, result_to_validate, fuzzer_intrinsics,
                       heuristics_passed, idx_to_use,
                       disable_fuzz_build_and_test, folders_with_results,
                       outdir, github_repo, language, introspector_report):
  """For a given result, will write the harness and build to the file system
  and run the OSS-Fuzz `compile` command to verify that the build script +
  harness builds."""

  logger.info('Fuzzer gen dir:')
  logger.info(os.path.basename(test_dir) + f'-fuzzgen-{idx_to_use}')

  fuzzer_gen_dir = os.path.join(
      '/src',
      os.path.basename(test_dir) + f'-fuzzgen-{idx_to_use}')
  logger.info('- %s', fuzzer_gen_dir)
  if os.path.isdir(fuzzer_gen_dir):
    shutil.rmtree(fuzzer_gen_dir)
  os.mkdir(fuzzer_gen_dir)

  _, _, fuzzer_target_file, _ = get_language_defaults(language)

  # Dump introspector report so we can debug it
  with open(os.path.join(fuzzer_gen_dir, 'summary.json'), 'w') as f:
    json.dump(introspector_report, f)

  # Write the fuzzer in the directory where we store the source code, just
  # for covenience so we can easily see later.
  with open(os.path.join(fuzzer_gen_dir, 'build.sh'), 'w') as f:
    f.write(result_to_validate['build-script'])
  with open(os.path.join(fuzzer_gen_dir, os.path.basename(fuzzer_target_file)),
            'w') as f:
    f.write(result_to_validate['source'])

  # Write the build/fuzzer files as used by oss-fuzz and the build script.
  with open(result_to_validate['fuzzer-file'], 'w') as f:
    f.write(result_to_validate['source'])
  with open('/src/build.sh', 'w') as f:
    f.write(result_to_validate['build-script'])

  # Skip build process if specified.
  if disable_fuzz_build_and_test:
    return

  # Cleanup any existing fuzzers
  if os.path.isfile(result_to_validate['fuzzer-out']):
    os.remove(result_to_validate['fuzzer-out'])

  modified_env = os.environ
  modified_env['SANITIZER'] = 'address'
  build_out = open(os.path.join(fuzzer_gen_dir, 'fuzz-build.out'), 'w')
  build_err = open(os.path.join(fuzzer_gen_dir, 'fuzz-build.err'), 'w')
  try:
    subprocess.check_call('compile',
                          shell=True,
                          env=modified_env,
                          stdout=build_out,
                          stderr=build_err)
    logger.info('[+] Harness build succeeded')
    build_returned_error = False
  except subprocess.CalledProcessError:
    logger.info('[+] Harness build failed')
    build_returned_error = True

  destination_folder = os.path.join(
      fuzzer_gen_dir,
      os.path.basename(test_dir) + f'-fuzzer-generated-{idx_to_use}')

  folders_with_results.add(fuzzer_gen_dir)
  if os.path.isfile(result_to_validate['fuzzer-out']):
    shutil.copy(result_to_validate['fuzzer-out'], destination_folder)

  # Copy artifacts to fuzzer_gen_dir if build was successful.
  if build_returned_error is False:
    heuristics_passed[fuzzer_intrinsics['autogen-id']] = True

  # Write the prompt to out
  with open(os.path.join(fuzzer_gen_dir, 'prompt.txt'), 'w') as f:
    f.write(fuzzer_intrinsics['prompt'])

  # Run the fuzzer and observer error
  if not os.path.isfile('/src/generated-fuzzer'):
    logger.info('No fuzzing harness executable')
    logger.info('Copying [%s] to [%s]', fuzzer_gen_dir,
                os.path.join(outdir, os.path.basename(fuzzer_gen_dir)))
    shutil.copytree(fuzzer_gen_dir,
                    os.path.join(outdir, os.path.basename(fuzzer_gen_dir)))
    return

  logger.info('Running fuzzer')
  run_out = open(os.path.join(fuzzer_gen_dir, 'fuzz-run.out'), 'w')
  run_err = open(os.path.join(fuzzer_gen_dir, 'fuzz-run.err'), 'w')
  corpus_dir = os.path.join(fuzzer_gen_dir, 'corpus',
                            os.path.basename(result_to_validate['fuzzer-out']))
  os.makedirs(corpus_dir)
  try:
    subprocess.check_call(
        (f'{result_to_validate["fuzzer-out"]} -max_total_time=20'
         f' {corpus_dir}'),
        shell=True,
        env=modified_env,
        stdout=run_out,
        stderr=run_err)
    build_returned_error = False
    logger.info('[+] Harness build succeeded')
  except subprocess.CalledProcessError:
    logger.info('[+] Harness build failed')
    build_returned_error = True

  logger.info('Running fuzzer without leak detection')
  run_out = open(os.path.join(fuzzer_gen_dir, 'fuzz-no-leak-run.out'), 'w')
  run_err = open(os.path.join(fuzzer_gen_dir, 'fuzz-no-leak-run.err'), 'w')
  corpus_no_leak = os.path.join(
      fuzzer_gen_dir, 'corpus',
      os.path.basename(result_to_validate['fuzzer-out']) + '-no-leak')
  os.makedirs(corpus_no_leak, exist_ok=True)
  try:
    subprocess.check_call(
        (f'{result_to_validate["fuzzer-out"]} -max_total_time=20 '
         f'-detect_leaks=0 {corpus_no_leak}'),
        shell=True,
        env=modified_env,
        stdout=run_out,
        stderr=run_err)
  except subprocess.CalledProcessError:
    logger.info('[+] Running without leak detection failed')

  logger.info('Copying 2 [%s] to [%s]', fuzzer_gen_dir,
              os.path.join(outdir, os.path.basename(fuzzer_gen_dir)))
  shutil.copytree(fuzzer_gen_dir,
                  os.path.join(outdir, os.path.basename(fuzzer_gen_dir)))

  # Create an OSS-Fuzz integration and ClusterFuzzLite integration
  create_clean_oss_fuzz_from_success(
      github_repo, os.path.join(outdir, os.path.basename(fuzzer_gen_dir)),
      language)
  create_clean_clusterfuzz_lite_from_success(
      github_repo, os.path.join(outdir, os.path.basename(fuzzer_gen_dir)),
      language)


def create_clean_oss_fuzz_from_success(github_repo: str, success_dir: str,
                                       language: str) -> None:
  """Converts a successful out dir into a working OSS-Fuzz project."""
  oss_fuzz_folder = os.path.join(success_dir, 'oss-fuzz-project')
  os.makedirs(oss_fuzz_folder)

  # Project yaml
  project_yaml = {
      'homepage': github_repo,
      'language': language,
      'primary_contact': 'add_your_email@here.com',
      'main_repo': github_repo
  }
  with open(os.path.join(oss_fuzz_folder, 'project.yaml'), 'w') as project_out:
    yaml.dump(project_yaml, project_out)

  # Copy fuzzer
  _, _, fuzzer_target_file, _ = get_language_defaults(language)
  shutil.copy(
      os.path.join(success_dir, os.path.basename(fuzzer_target_file)),
      os.path.join(oss_fuzz_folder,
                   os.path.basename(fuzzer_target_file).replace('empty-', '')))

  # Create Dockerfile
  project_repo_dir = github_repo.split('/')[-1]
  dockerfile = templates.CLEAN_OSS_FUZZ_DOCKER.format(
      repo_url=github_repo, project_repo_dir=project_repo_dir)
  with open(os.path.join(oss_fuzz_folder, 'Dockerfile'), 'w') as docker_out:
    docker_out.write(dockerfile)

  # Build file
  with open(os.path.join(success_dir, 'build.sh'), 'r') as f:
    build_content = f.read()

  clean_build_content = convert_test_build_to_clean_build(
      build_content, project_repo_dir)

  with open(os.path.join(oss_fuzz_folder, 'build.sh'), 'w') as f:
    f.write(clean_build_content)


def create_clean_clusterfuzz_lite_from_success(github_repo: str,
                                               success_dir: str,
                                               language: str) -> None:
  """Converts a successful out dir into a working ClusterFuzzLite project."""
  cflite_folder = os.path.join(success_dir, 'clusterfuzz-lite-project')
  os.makedirs(cflite_folder)

  # Project yaml
  project_yaml = {
      'language': language,
  }
  with open(os.path.join(cflite_folder, 'project.yaml'), 'w') as project_out:
    yaml.dump(project_yaml, project_out)

  # Copy fuzzer
  _, _, fuzzer_target_file, _ = get_language_defaults(language)
  shutil.copy(
      os.path.join(success_dir, os.path.basename(fuzzer_target_file)),
      os.path.join(cflite_folder,
                   os.path.basename(fuzzer_target_file).replace('empty-', '')))

  # Create Dockerfile
  project_repo_dir = github_repo.split('/')[-1]
  dockerfile = templates.CLEAN_DOCKER_CFLITE.format(
      project_repo_dir=project_repo_dir)
  with open(os.path.join(cflite_folder, 'Dockerfile'), 'w') as docker_out:
    docker_out.write(dockerfile)

  # Build file
  with open(os.path.join(success_dir, 'build.sh'), 'r') as f:
    build_content = f.read()

  clean_build_content = convert_test_build_to_clean_build(
      build_content, project_repo_dir)

  with open(os.path.join(cflite_folder, 'build.sh'), 'w') as f:
    f.write(clean_build_content)

  with open(os.path.join(cflite_folder, 'cflite_pr.yml'), 'w') as f:
    f.write(templates.CFLITE_TEMPLATE)


def convert_test_build_to_clean_build(test_build_script: str,
                                      project_repo_dir: str) -> str:
  """Rewrites a build.sh used during testing to a proper OSS-Fuzz build.sh."""
  split_build_content = test_build_script.split('\n')

  # Extract the test folder name
  original_build_folder = split_build_content[1].split('/')[-1]

  # Remove the lines used in the testing build script to navigate test folders.
  clean_build_content_lines = split_build_content[:1] + split_build_content[4:]

  # Make adjustments in the build to convert a test script to a clean script:
  # 1) Output fuzzer to $OUT/fuzzer instead of /src/generated-fuzzer
  # 2) Call the fuzzer 'fuzzer' instead of 'empty-fuzzer'
  # 3) Use '$SRC/' instead of '/src/'
  # 4) Rewrite file paths from test build directory to cloned directory, to
  # adjust e.g. library and include paths.
  clean_build_content = '\n'.join(clean_build_content_lines).replace(
      '/src/generated-fuzzer',
      '$OUT/fuzzer').replace('empty-fuzzer', 'fuzzer').replace(
          '/src/', '$SRC/').replace(original_build_folder, project_repo_dir)
  return clean_build_content


def append_to_report(outdir, msg):
  if not os.path.isdir(outdir):
    os.mkdir(outdir)
  report_path = os.path.join(outdir, 'report.txt')
  with open(report_path, 'a+') as f:
    f.write(msg + '\n')


def load_introspector_report():
  """Extract introspector as python dictionary from local run."""
  if not os.path.isfile(os.path.join(INTROSPECTOR_OSS_FUZZ_DIR,
                                     'summary.json')):
    return None
  with open(os.path.join(INTROSPECTOR_OSS_FUZZ_DIR, 'summary.json'), 'r') as f:
    summary_report = json.loads(f.read())

  # Get all functions folder
  if not os.path.isfile(
      os.path.join(INTROSPECTOR_OSS_FUZZ_DIR, INTROSPECTOR_ALL_FUNCTIONS_FILE)):
    return None
  with open(
      os.path.join(INTROSPECTOR_OSS_FUZZ_DIR, INTROSPECTOR_ALL_FUNCTIONS_FILE),
      'r') as f:
    all_functions_list = json.loads(f.read())

  summary_report['MergedProjectProfile']['all-functions'] = all_functions_list
  return summary_report


def get_heuristics_to_use() -> List[Type[FuzzHeuristicGeneratorBase]]:
  """Returns the list of possible heuristics to use for harness generation."""
  heuristics_to_use = os.getenv('GENERATOR_HEURISTICS', 'all')
  heuristics_to_apply = []
  all_possible_heuristics = [
      FuzzerGenHeuristic6, FuzzerGenHeuristic5, FuzzerGenHeuristic4,
      FuzzerGenHeuristic3, FuzzerGenHeuristic2, FuzzerGenHeuristic1
  ]
  if heuristics_to_use == 'all':
    heuristics_to_apply = all_possible_heuristics
  else:
    possible_heuristics = set(heuristics_to_use.split(','))
    for heuristic in all_possible_heuristics:
      if heuristic.name in possible_heuristics:
        heuristics_to_apply.append(heuristic)
  return heuristics_to_apply


def auto_generate(github_url,
                  disable_testing_build_scripts=False,
                  disable_fuzzgen=False,
                  disable_fuzz_build_and_test=False,
                  outdir=''):
  """Generates build script and fuzzer harnesses for a GitHub repository."""
  target_source_path = os.path.join(os.getcwd(), github_url.split('/')[-1])
  dst_folder = github_url.split('/')[-1]

  # clone the base project into a dedicated folder
  if not os.path.isdir(target_source_path):
    subprocess.check_call(
        f'git clone --recurse-submodules {github_url} {dst_folder}', shell=True)

  # Stage 1: Build script generation
  language = determine_project_language(target_source_path)
  logger.info('Target language: %s', language)
  append_to_report(outdir, f'Target language: {language}')

  # record the path
  logger.info('[+] Extracting build scripts statically')
  all_build_scripts: List[
      Tuple[str, str, build_generator.
            AutoBuildContainer]] = build_generator.extract_build_suggestions(
                target_source_path, 'test-fuzz-build-')

  # return now if we don't need to test build scripts
  if disable_testing_build_scripts is True:
    return

  # Check each of the build scripts.
  logger.info('[+] Testing build suggestions')
  build_results = build_generator.raw_build_evaluation(all_build_scripts)
  logger.info('Checking results of %d build generators', len(build_results))
  for test_dir, build_worker in build_results.items():
    build_heuristic = build_worker.build_suggestion.heuristic_id
    static_libs = build_worker.executable_files_build['static-libs']

    append_to_report(
        outdir,
        f'build success: {build_heuristic} :: {test_dir} :: {static_libs}')
    logger.info('%s : %s : %s', build_heuristic, test_dir, static_libs)

  # For each of the auto generated build scripts identify the
  # static libraries resulting from the build.
  refine_static_libs(build_results)

  # Stage 2: perform program analysis to extract data to be used for
  # harness generation.
  build_empty_fuzzers(build_results, language)

  # Stage 3: Harness generation and harness testing.
  # We now know for which versions we can generate a base fuzzer.
  # Continue by runnig an introspector build using the auto-generated
  # build scripts but fuzz introspector as the sanitier. The introspector
  # build will analyze all code build in the project, meaning we will
  # extract build data for code linked in e.g. samples and more during
  # the build. The consequence is we will have a lot more data than if
  # we only were to build the base fuzzer using introspector builds.
  # Then, proceed to use the generated program analysis data as arguments
  # to heuristics which will generate fuzzers.
  # We need to run introspector per build, because we're essentially not
  # sure if the produced binary files are the same. We could maybe optimize
  # this to check if there are differences in build output.
  heuristics_passed = {}
  folders_with_results = set()
  logger.info('Going through %d build results to generate fuzzers',
              len(build_results))
  for test_dir, build_worker in build_results.items():
    logger.info('Checking build heuristic: %s',
                build_worker.build_suggestion.heuristic_id)

    # Skip if build suggestion did not work with an empty fuzzer.
    if not build_worker.base_fuzz_build:
      logger.info('Build failed, skipping')
      continue

    # Run Fuzz Introspector on the target
    logger.info('Running introspector build')
    if os.path.isdir(INTROSPECTOR_OSS_FUZZ_DIR):
      shutil.rmtree(INTROSPECTOR_OSS_FUZZ_DIR)

    _, fuzzer_build_cmd = run_introspector_on_dir(build_worker, test_dir,
                                                  language)

    if os.path.isdir(INTROSPECTOR_OSS_FUZZ_DIR):
      logger.info('Introspector build success')
    else:
      logger.info('Failed to get introspector results')

    # Identify the relevant functions
    introspector_report = load_introspector_report()
    if introspector_report is None:
      continue

    #sys.exit(0)
    func_count = len(
        introspector_report['MergedProjectProfile']['all-functions'])
    logger.info('Found a total of %d functions.', func_count)
    append_to_report(outdir, 'Introspector analysis done')

    logger.info('Test dir: %s', str(test_dir))
    all_header_files = get_all_header_files(get_all_files_in_path(test_dir))

    append_to_report(outdir, f'Total functions in {test_dir} : {func_count}')

    if disable_fuzzgen:
      continue

    # At this point we have:
    # - A list of functions from the introspector analyses
    # - A list of build scripts that can auto-build the project
    # - A list of the static libraries created during the compilation process
    # We can now proceed to apply heuristics that use this data to generate
    # fuzzing harnesses and build scripts for these harnesses.
    heuristics_to_apply = get_heuristics_to_use()
    idx = 0
    logger.info(
        'Running target functions through %s fuzzer harness generation '
        'heuristics', len(heuristics_to_apply))
    for heuristic_class in heuristics_to_apply:
      if heuristic_class.language != language:
        continue
      # Initialize heuristic with the fuzz introspector data
      heuristic = heuristic_class(introspector_report, all_header_files,
                                  test_dir)
      logger.info('Applying %s', heuristic.name)

      heuristic.github_url = github_url
      harness_builds_to_validate = generate_harness_intrinsics(
          heuristic, build_results, language, test_dir, fuzzer_build_cmd)

      # Build the fuzzer for each project
      logger.info('Fuzzer harnesses to evaluate: %d',
                  len(harness_builds_to_validate))
      for result_to_validate in harness_builds_to_validate:
        logger.info('Evaluating harness')
        fuzzer_intrinsics = result_to_validate['fuzzer-intrinsics']
        # Make a directory and store artifacts there
        evaluate_heuristic(test_dir, result_to_validate, fuzzer_intrinsics,
                           heuristics_passed, idx, disable_fuzz_build_and_test,
                           folders_with_results, outdir, github_url, language,
                           introspector_report)
        idx += 1

  # Show those that succeeded.
  for hp in heuristics_passed:
    logger.info('Success: %s', hp)


def parse_commandline():
  """Commandline parser."""
  parser = argparse.ArgumentParser()
  parser.add_argument('repo', help='Github url of target')
  parser.add_argument('--disable-build-test',
                      action='store_true',
                      help='disables')
  parser.add_argument(
      '--disable-fuzzgen',
      action='store_true',
      help='disables auto generation of fuzzers, only build will run.')
  parser.add_argument('--disable-fuzz-build-and-test',
                      action='store_true',
                      help='disables building and testing of fuzzers')
  parser.add_argument('--out', '-o', help='Directory to store successful runs')
  parser.add_argument('--targets-per-heuristic',
                      '-t',
                      help='Targets per heuristic.',
                      type=int,
                      default=5)
  parser.add_argument('--model',
                      '-m',
                      help='Model to use for auto generation',
                      type=str)
  return parser


def setup_logging():
  logging.basicConfig(level=logging.INFO, format=LOG_FMT)


def main():
  global MAX_FUZZ_PER_HEURISTIC

  parser = parse_commandline()
  args = parser.parse_args()
  setup_logging()

  setup_model(args.model)

  append_to_report(args.out, f'Analysing: {args.repo}')
  MAX_FUZZ_PER_HEURISTIC = args.targets_per_heuristic

  auto_generate(args.repo, args.disable_build_test, args.disable_fuzzgen,
                args.disable_fuzz_build_and_test, args.out)


if __name__ == '__main__':
  main()
