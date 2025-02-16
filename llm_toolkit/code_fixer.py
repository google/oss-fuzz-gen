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
"""Fixing fuzz target with LLM."""

import argparse
import logging
import os
import re
import sys
from typing import Callable, Optional

from data_prep.project_context import context_introspector
from experiment import benchmark as benchmarklib
from llm_toolkit import models
from llm_toolkit import output_parser as parser
from llm_toolkit import prompt_builder

logger = logging.getLogger(__name__)

ERROR_LINES = 20
NO_MEMBER_ERROR_REGEX = r"error: no member named '.*' in '([^':]*):?.*'"
FILE_NOT_FOUND_ERROR_REGEX = r"fatal error: '([^']*)' file not found"
UNDEFINED_REF_ERROR_REGEX = r"undefined reference to `([^']*)'"
UNKNOWN_TYPE_ERROR = 'error: unknown type name'

# The following strings identify errors when a C fuzz target attempts to use
# FuzzedDataProvider.
FALSE_FUZZED_DATA_PROVIDER_ERROR = 'include/fuzzer/FuzzedDataProvider.h:16:10:'
FALSE_EXTERN_KEYWORD_ERROR = 'expected identifier or \'(\'\nextern "C"'
FDP_INCLUDE_STATEMENT = '#include <fuzzer/FuzzedDataProvider.h>'


def parse_args():
  """Parses command line arguments."""
  argparser = argparse.ArgumentParser(
      description='Fix the raw fuzz targets generated by LLM.')
  argparser.add_argument(
      '-t',
      '--target-dir',
      type=str,
      default='./fixed_targets',
      help='The directory to store all fixed LLM-generated targets.')
  argparser.add_argument(
      '-o',
      '--intermediate-output-dir',
      type=str,
      default='./code_fix_output',
      help=('The directory to store all intermediate output files (LLM prompt, '
            'rawoutput).'))
  argparser.add_argument('-p',
                         '--project',
                         type=str,
                         required=True,
                         help='The project name.')
  argparser.add_argument('-f',
                         '--function',
                         type=str,
                         required=True,
                         help='The function name.')
  argparser.add_argument('-l',
                         '--log',
                         type=str,
                         required=True,
                         help='The build log file containing the error to fix.')

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


def get_target_files(target_dir: str) -> list[str]:
  """Returns the fuzz target files in the raw target directory."""
  return [
      os.path.join(target_dir, f)
      for f in os.listdir(target_dir)
      if benchmarklib.is_c_file(f) or benchmarklib.is_cpp_file(f)
  ]


def collect_specific_fixes(project: str,
                           file_name: str) -> list[Callable[[str], str]]:
  """Returns a list code fix functions given the language and |project|."""
  required_fixes = set()
  if benchmarklib.is_cpp_file(file_name):
    required_fixes = required_fixes.union([
        append_extern_c,
        insert_cstdint,
        insert_cstdlib,
    ])

  # TODO(Dongge): Remove this.
  if benchmarklib.is_c_file(file_name):
    required_fixes = required_fixes.union([
        insert_stdint,
        include_builtin_library,
    ])

  # TODO(Dongge): Remove this.
  if project == 'libpng-proto':
    required_fixes = required_fixes.union([
        remove_nonexist_png_functions,
        include_pngrio,
        remove_const_from_png_symbols,
    ])

  return list(required_fixes)


def apply_specific_fixes(content: str,
                         required_fixes: list[Callable[[str], str]]) -> str:
  """Fixes frequent errors in |raw_content| and returns fixed content."""
  for required_fix in required_fixes:
    content = required_fix(content)

  return content


def fix_all_targets(target_dir: str, project: str):
  """Reads raw content, applies fixes, and saves the fixed content."""
  for file in get_target_files(target_dir):
    with open(file) as raw_file:
      raw_content = raw_file.read()
    specific_fixes = collect_specific_fixes(project, file)
    fixed_content = apply_specific_fixes(raw_content, specific_fixes)
    with open(os.path.join(target_dir, os.path.basename(file)),
              'w+') as fixed_file:
      fixed_file.write(fixed_content)


# ========================= Specific Fixes ========================= #
def append_extern_c(raw_content: str) -> str:
  """Appends `extern "C"` before fuzzer entry `LLVMFuzzerTestOneInput`."""
  pattern = r'int LLVMFuzzerTestOneInput'
  replacement = f'extern "C" {pattern}'
  fixed_content = re.sub(pattern, replacement, raw_content)
  return fixed_content


def insert_cstdlib(raw_content: str) -> str:
  """Includes `cstdlib` library."""
  fixed_content = f'#include <cstdlib>\n{raw_content}'
  return fixed_content


def insert_cstdint(raw_content: str) -> str:
  """Includes `cstdint` library."""
  fixed_content = f'#include <cstdint>\n{raw_content}'
  return fixed_content


def insert_stdint(content: str) -> str:
  """Includes `stdint` library."""
  include_stdint = '#include <stdint.h>\n'
  if include_stdint not in content:
    content = f'{include_stdint}{content}'
  return content


def remove_nonexist_png_functions(content: str) -> str:
  """Removes non-exist functions in libpng-proto."""
  non_exist_functions = [
      r'.*png_init_io.*',
      r'.*png_set_write_fn.*',
      r'.*png_set_compression_level.*',
      r'.*.png_write_.*',
  ]
  for pattern in non_exist_functions:
    content = re.sub(pattern, '', content)
  return content


def include_builtin_library(content: str) -> str:
  """Includes builtin libraries when its function was invoked."""
  library_function_dict = {
      '#include <stdlib.h>': [
          'malloc',
          'calloc',
          'free',
      ],
      '#include <string.h>': ['memcpy',]
  }
  for library, functions in library_function_dict.items():
    use_lib_functions = any(f in content for f in functions)
    if use_lib_functions and not library in content:
      content = f'{library}\n{content}'
  return content


def include_pngrio(content: str) -> str:
  """Includes <pngrio.c> when using its functions."""
  functions = [
      'png_read_data',
      'png_default_read_data',
  ]
  use_pngrio_funcitons = any(f in content for f in functions)
  include_pngrio_stmt = '#include "pngrio.c"'

  if use_pngrio_funcitons and not include_pngrio_stmt in content:
    content = f'{include_pngrio}\n{content}'
  return content


def remove_const_from_png_symbols(content: str) -> str:
  """Removes const from png types."""
  re.sub(r'png_const_', 'png_', content)
  return content


# ========================= LLM Fixes ========================= #


def extract_error_message(log_path: str, project_target_basename: str,
                          language: str) -> list[str]:
  """Extracts error message and its context from the file in |log_path|."""

  with open(log_path) as log_file:
    # A more accurate way to extract the error message.
    log_lines = log_file.readlines()

  errors = extract_error_from_lines(log_lines, project_target_basename,
                                    language)
  if not errors:
    logger.warning('Failed to parse error message from %s.', log_path)
  return errors


def extract_error_from_lines(log_lines: list[str], project_target_basename: str,
                             language: str) -> list[str]:
  """Extracts error message and its context from the file in |log_path|."""
  # Error message extraction for Java projects
  if language == 'jvm':
    started = False
    errors = []
    for log_line in log_lines:
      if started:
        errors.append(log_line)
        if log_line == 'ERROR:__main__:Building fuzzers failed.':
          break
      else:
        if ': error:' in log_line:
          errors.append(log_line)
          started = True

    return errors

  # Error message extraction for Rust projects
  if language == 'rust':
    started = False
    errors = []
    for log_line in log_lines:
      if started:
        errors.append(log_line)
        if log_line == 'error: could not compile':
          break
      else:
        if log_line.startswith(('error[E', 'warning:')):
          errors.append(log_line)
          started = True

    return errors

  target_name, _ = os.path.splitext(project_target_basename)

  error_lines_range: list[Optional[int]] = [None, None]
  temp_range: list[Optional[int]] = [None, None]

  error_start_pattern = r'\S*' + target_name + r'(\.\S*)?:\d+:\d+: .+: .+\n?'
  error_include_pattern = (r'In file included from \S*' + target_name +
                           r'(\.\S*)?:\d+:\n?')
  error_end_pattern = r'.*\d+ errors? generated.\n?'

  error_keywords = [
      'multiple definition of',
      'undefined reference to',
  ]
  errors = []
  unique_symbol = set()
  for i, line in enumerate(log_lines):
    # Add GNU ld errors in interest.
    found_keyword = False
    for keyword in error_keywords:
      if keyword not in line:
        continue
      found_keyword = True
      symbol = line.split(keyword)[-1]
      if symbol not in unique_symbol:
        unique_symbol.add(symbol)
        errors.append(line.rstrip())
      break
    if found_keyword:
      continue

    # Add clang/clang++ diagnostics.
    if (temp_range[0] is None and (re.fullmatch(error_include_pattern, line) or
                                   re.fullmatch(error_start_pattern, line))):
      temp_range[0] = i
    if temp_range[0] is not None and re.fullmatch(error_end_pattern, line):
      temp_range[1] = i - 1  # Exclude current line.
      # In case the original fuzz target was written in C and building with
      # clang failed, and building with clang++ also failed, we take the
      # error from clang++, which comes after.
      error_lines_range = temp_range
      temp_range = [None, None]

  if error_lines_range[0] is not None and error_lines_range[1] is not None:
    errors.extend(
        line.rstrip()
        for line in log_lines[error_lines_range[0]:error_lines_range[1] + 1])

  return group_error_messages(errors)


def group_error_messages(error_lines: list[str]) -> list[str]:
  """Groups multi-line error block into one string"""
  state_unknown = 'UNKNOWN'
  state_include = 'INCLUDE'
  state_diag = 'DIAG'

  diag_error_pattern = re.compile(r'(\S*):\d+:\d+: (.+): (.+)')
  include_error_pattern = re.compile(r'In file included from (\S*):\d+:')
  error_blocks = []
  curr_block = []
  src_file = ''
  curr_state = state_unknown
  for line in error_lines:
    if not line:  # Trim empty lines.
      continue

    diag_match = diag_error_pattern.fullmatch(line)
    include_match = include_error_pattern.fullmatch(line)

    if diag_match:
      err_src = diag_match.group(1)
      severity = diag_match.group(2)

      # Matched a note diag line under another diag,
      # giving help info to fix the previous error.
      if severity == 'note':
        curr_block.append(line)
        continue

      # Matched a diag line but under an included file line,
      # indicating the specific error in the included file,
      if curr_state == state_include and err_src != src_file:
        curr_block.append(line)
        continue

      curr_state = state_diag
      if curr_block:
        error_blocks.append('\n'.join(curr_block))
        curr_block = []

    if include_match:
      src_file = include_match.group(1)
      curr_state = state_include
      if curr_block:
        error_blocks.append('\n'.join(curr_block))
        curr_block = []

    # Keep unknown error lines separated.
    if curr_state == state_unknown and curr_block:
      error_blocks.append('\n'.join(curr_block))
      curr_block = []

    curr_block.append(line)

  if curr_block:
    error_blocks.append('\n'.join(curr_block))
  return error_blocks


def llm_fix(ai_binary: str, target_path: str, benchmark: benchmarklib.Benchmark,
            llm_fix_id: int, error_desc: Optional[str], errors: list[str],
            fixer_model_name: str, language: str, jvm_cov_fix: bool) -> None:
  """Reads and fixes |target_path| in place with LLM based on |error_log|."""
  fuzz_target_source_code = parser.parse_code(target_path)

  _, target_ext = os.path.splitext(os.path.basename(target_path))
  response_dir = f'{os.path.splitext(target_path)[0]}-F{llm_fix_id}'
  os.makedirs(response_dir, exist_ok=True)
  prompt_path = os.path.join(response_dir, 'prompt.txt')

  apply_llm_fix(ai_binary,
                benchmark,
                fuzz_target_source_code,
                error_desc,
                errors,
                prompt_path,
                response_dir,
                language,
                jvm_cov_fix,
                fixer_model_name,
                temperature=0.5 - llm_fix_id * 0.04)

  fixed_code_candidates = []
  for file in os.listdir(response_dir):
    if not parser.is_raw_output(file):
      continue
    fixed_code_path = os.path.join(response_dir, file)
    fixed_code = parser.parse_code(fixed_code_path)
    fixed_code_candidates.append([fixed_code_path, fixed_code])

  if not fixed_code_candidates:
    logger.info('LLM did not generate rawoutput for %s', prompt_path)
    return

  # TODO(Dongge): Use the common vote:
  # LLM gives multiple responses to one query. In many experiments, I
  # found the code compartment of some of the responses are exactly the same. In
  # these cases, we can use the most common code of all responses as it could be
  # a safer choice. Currently, we prefer the longest code to encourage code
  # complexity.
  # TODO(Dongge): Exclude the candidate if it is identical to the original
  # code.
  preferred_fix_path, preferred_fix_code = max(fixed_code_candidates,
                                               key=lambda x: len(x[1]))
  logger.info('Will use the longest fix: %s',
              os.path.relpath(preferred_fix_path))
  preferred_fix_name, _ = os.path.splitext(preferred_fix_path)
  fixed_target_path = os.path.join(response_dir,
                                   f'{preferred_fix_name}{target_ext}')
  parser.save_output(preferred_fix_code, fixed_target_path)
  parser.save_output(preferred_fix_code, target_path)


def apply_llm_fix(ai_binary: str,
                  benchmark: benchmarklib.Benchmark,
                  fuzz_target_source_code: str,
                  error_desc: Optional[str],
                  errors: list[str],
                  prompt_path: str,
                  response_dir: str,
                  language: str,
                  jvm_cov_fix: bool,
                  fixer_model_name: str = models.DefaultModel.name,
                  temperature: float = 0.4):
  """Queries LLM to fix the code."""
  fixer_model = models.LLM.setup(
      ai_binary=ai_binary,
      name=fixer_model_name,
      num_samples=1,
      temperature=temperature,
  )

  if language == 'jvm':
    builder = prompt_builder.JvmErrorFixingBuilder(fixer_model, benchmark,
                                                   fuzz_target_source_code,
                                                   errors, jvm_cov_fix)
    prompt = builder.build([], None, None)
    prompt.save(prompt_path)
  else:
    builder = prompt_builder.DefaultTemplateBuilder(fixer_model)

    context = collect_context(benchmark, errors)
    instruction = collect_instructions(benchmark, errors,
                                       fuzz_target_source_code)
    prompt = builder.build_fixer_prompt(benchmark, fuzz_target_source_code,
                                        error_desc, errors, context,
                                        instruction)
    prompt.save(prompt_path)

  fixer_model.query_llm(prompt, response_dir)


def collect_context(benchmark: benchmarklib.Benchmark,
                    errors: list[str]) -> str:
  """Collects the useful context to fix the errors."""
  if not errors:
    return ''

  context = ''
  for error in errors:
    context += _collect_context_no_member(benchmark, error)

  return context


def _collect_context_no_member(benchmark: benchmarklib.Benchmark,
                               error: str) -> str:
  """Collects the useful context to fix 'no member in' errors."""
  matched = re.search(NO_MEMBER_ERROR_REGEX, error)
  if not matched:
    return ''
  target_type = matched.group(1)
  ci = context_introspector.ContextRetriever(benchmark)
  return ci.get_type_def(target_type)


def collect_instructions(benchmark: benchmarklib.Benchmark, errors: list[str],
                         fuzz_target_source_code: str) -> str:
  """Collects the useful instructions to fix the errors."""
  if not errors:
    return ''

  instruction = ''
  for error in errors:
    instruction += _collect_instruction_file_not_found(benchmark, error,
                                                       fuzz_target_source_code)
    instruction += _collect_instruction_undefined_reference(
        benchmark, error, fuzz_target_source_code)
  instruction += _collect_instruction_fdp_in_c_target(benchmark, errors,
                                                      fuzz_target_source_code)
  instruction += _collect_instruction_no_goto(fuzz_target_source_code)
  instruction += _collect_instruction_builtin_libs_first(benchmark, errors)
  instruction += _collect_instruction_extern(benchmark)
  instruction += _collect_consume_buffers(fuzz_target_source_code)

  return instruction


def _collect_instruction_undefined_reference(
    benchmark: benchmarklib.Benchmark, error: str,
    fuzz_target_source_code: str) -> str:
  """Collects the instructions to fix the 'undefined reference' errors."""
  matched_funcs = re.findall(UNDEFINED_REF_ERROR_REGEX, error)
  if not matched_funcs:
    return ''
  instruction = ''
  for undefined_func in matched_funcs:
    if undefined_func == 'LLVMFuzzerTestOneInput':
      continue
    ci = context_introspector.ContextRetriever(benchmark)
    header_file = ci.get_prefixed_header_file_by_name(undefined_func)
    if header_file and header_file not in fuzz_target_source_code:
      instruction += (
          'You must add the following #include statement to fix the error of '
          f'<error>undefined reference to {undefined_func}</error>:\n<code>\n'
          f'{header_file}\n</code>.\n')
    elif not header_file and benchmark.is_c_projcet:
      instruction += (
          f'You must remove the function <code>{undefined_func}</code> from the'
          ' generated fuzz target, because the function does not exist.\n')
    elif not header_file or header_file in fuzz_target_source_code:
      # C project: NO header file found, or
      # C++: Cannot map demangled C++ function name to signature
      source_file = ci.get_prefixed_source_file(undefined_func)
      if not source_file and benchmark.function_name in undefined_func:
        source_file = ci.get_prefixed_source_file()
      if source_file:
        if header_file:
          # To avoid redefinition.
          instruction += ('You must remove the following statement\n<code>\n'
                          f'{header_file}</code>\n')
        instruction += (
            'You must add the following #include statement to fix the error of '
            f"<error>undefined reference to `{undefined_func}'</error>:\n"
            f'<code>\n{source_file}\n</code>.\n')
    else:
      instruction += (
          f"To fix <error>undefined reference to `{undefined_func}'</error>,"
          'check the library documentation (e.g. README.md, comments) for '
          'special instructions, such as required macros or specific inclusion '
          'methods. Ensure any necessary definitions or inclusions are '
          'correctly implemented in your generated fuzz target, following the '
          "library's guidance.")
    if not instruction:
      instruction += (
          f"To fix <error>undefined reference to `{undefined_func}'</error>,"
          'check the library documentation (e.g. README.md, comments) for '
          'special instructions, such as required macros or specific inclusion '
          'methods. Ensure any necessary definitions or inclusions are '
          'correctly implemented in your generated fuzz target, following the '
          "library's guidance.")
  return instruction


def _collect_instruction_file_not_found(benchmark: benchmarklib.Benchmark,
                                        error: str,
                                        fuzz_target_source_code: str) -> str:
  """Collects the useful instruction to fix 'file not found' errors."""
  matched = re.search(FILE_NOT_FOUND_ERROR_REGEX, error)
  if not matched:
    return ''

  # Step 1: Say the file does not exist, do not include it.
  wrong_file = matched.group(1)
  instruction = (
      f'IMPORTANT: DO NOT include the header file {wrong_file} in the generated'
      ' fuzz target again, the file does not exist in the project-under-test.\n'
  )
  # Step 2: Suggest the header file of the same name as the wrong one.
  ci = context_introspector.ContextRetriever(benchmark)
  same_name_headers = ci.get_same_header_file_paths(wrong_file)
  if same_name_headers:
    statements = '\n'.join(
        [f'#include "{header}"' for header in same_name_headers])
    instruction += (
        f'Replace the non-existent <filepath>{wrong_file}</filepath> with the '
        'following statement, which share the same file name but exists under '
        'the correct path in the project-under-test:\n'
        f'<code>\n{statements}\n</code>\n')
    return instruction

  # Step 3: Suggest the header/source file of the function under test.
  function_file = ci.get_prefixed_header_file()
  if function_file and f'#include "{function_file}"' in fuzz_target_source_code:
    function_file_base_name = os.path.basename(function_file)

    instruction += (
        'In the generated code, ensure that the path prefix of <code>'
        f'{function_file_base_name}</code> is consistent with other include '
        f'statements related to the project ({benchmark.project}). For example,'
        'if another include statement is '
        f'<code>#include <{benchmark.project}/header.h></code>, you must modify'
        f' the path prefix in <code>#include "{function_file}"</code> to match '
        'it, resulting in <code>'
        f'#include <{benchmark.project}/{function_file_base_name}></code>.')
    return instruction

  if function_file:
    instruction += (
        f'If the non-existent <filepath>{wrong_file}</filepath> was included '
        f'for the declaration of <code>{benchmark.function_signature}</code>, '
        'you must replace it with the EXACT path of the actual file <filepath>'
        f'{function_file}</filepath>. For example:\n'
        f'<code>\n#include "{function_file}"\n</code>\n')

  # Step 4: Suggest similar alternatives.
  similar_headers = ci.get_similar_header_file_paths(wrong_file)
  if similar_headers:
    statements = '\n'.join(
        [f'#include "{header}"' for header in similar_headers])
    instruction += (
        'Otherwise, consider replacing it with some of the following statements'
        f'that may be correct alternatives:\n<code>\n{statements}\n</code>\n')
  return instruction


def _collect_instruction_fdp_in_c_target(benchmark: benchmarklib.Benchmark,
                                         errors: list[str],
                                         fuzz_target_source_code: str) -> str:
  """Collects instructions to ask LLM do not use FuzzedDataProvier in C targets
  """
  has_error_from_fdp = any(FALSE_EXTERN_KEYWORD_ERROR in error or
                           FALSE_FUZZED_DATA_PROVIDER_ERROR in error
                           for error in errors)
  include_fdp = FDP_INCLUDE_STATEMENT in fuzz_target_source_code
  is_c = benchmark.file_type == benchmarklib.FileType.C
  if (has_error_from_fdp or include_fdp) and is_c:
    return (
        'Please modify the generated C fuzz target to remove'
        '<code>FuzzedDataProvider</code> and replace all its functionalities '
        'with equivalent C code, because it will cause build failure in C fuzz '
        'targets.\nAlso, ensure the whole fuzz target must be compatible with '
        'plain C and does not include any C++ specific code or dependencies.\n')

  return ''


def _collect_instruction_no_goto(fuzz_target_source_code: str) -> str:
  """Collects the instruction to avoid using goto."""
  if 'goto' in fuzz_target_source_code:
    return (
        'EXTREMELY IMPORTANT: AVOID USING <code>goto</code>. If you have to '
        'write code using <code>goto</code>, you MUST MUST also declare all '
        'variables BEFORE the <code>goto</code>. Never introduce new variables '
        'after the <code>goto</code>.')
  return ''


def _collect_instruction_builtin_libs_first(benchmark: benchmarklib.Benchmark,
                                            errors: list[str]) -> str:
  """Collects the instructions to include builtin libraries first to fix
  unknown type name error."""
  # Refine this, e.g., check if the symbol is builtin or from a project file.
  if any(UNKNOWN_TYPE_ERROR in error for error in errors):
    return (
        'IMPORTANT: ALWAYS INCLUDE STANDARD LIBRARIES BEFORE PROJECT-SPECIFIC '
        f'({benchmark.project}) LIBRARIES. This order prevents errors like '
        '"unknown type name" for basic types. Additionally, include '
        'project-specific libraries that contain declarations before those that'
        'use these declared symbols.')
  return ''


def _collect_instruction_extern(benchmark: benchmarklib.Benchmark) -> str:
  """Collects the instructions to use extern "C" in C++ fuzz targets."""
  if not benchmark.needs_extern:
    return ''
  instruction = (
      f'IMPORTANT: The fuzz target ({benchmark.target_path}) is written in C++,'
      ' whereas the project-under-test ({PROJECT_NAME}) is written in C. All '
      f'headers, functions, and code from the {benchmark.project} project must '
      'be consistently wrapped in <code>extern "C"</code> to ensure error-free '
      'compilation and linkage between C and C++:\n<code>\nextern "C" {\n    //'
      'Include necessary C headers, source files, functions, and code here.\n}'
      '\n</code>\n')
  return instruction


def _collect_consume_buffers(fuzz_target_source_code: str) -> str:
  """Provides advice on the use of ConsumeBytes and ConsumeData"""

  instruction = ''

  for buffer_method in ['ConsumeBytes', 'ConsumeData']:
    if buffer_method in fuzz_target_source_code:
      instruction += (
          'IMPORTANT: the harness source code contains a call to `'
          f'{buffer_method}`. Whenever this function is used, you MUST validate'
          ' the size of the vector returned, and make sure that the size of the'
          f' vector is equal to argument given to `{buffer_method}`. If it is '
          'not equal, the harness should not proceed.\n')
      instruction += (
          f'Furthermore, consider changing {buffer_method} to '
          '`ConsumeRandomLengthString` for creating `char` buffers or strings. '
          'In most cases, `ConsumeRandomLengthString` is preferred, and '
          f'should be used instead of {buffer_method}\n')

  return instruction


def main():
  args = parse_args()
  fix_all_targets(args.target_dir, args.project)


if __name__ == '__main__':
  sys.exit(main())
