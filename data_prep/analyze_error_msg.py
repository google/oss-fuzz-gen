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
Analyze error messages to extend or replace with auxiliary information from
source code.
"""
import logging
import os
import re
from abc import abstractmethod

from data_prep import introspector
from experiment.benchmark import Benchmark


def get_minimum_filename(path: str) -> str:
  """Get the filename without parent directories and extension."""
  return os.path.splitext(os.path.basename(path))[0]


class ErrorAnalyzer:
  """Base compile error analyzer class."""

  def __init__(self, benchmark: Benchmark, errors: list[str]):
    self.benchmark = benchmark
    self.errors = self.group_errors(errors)

  @abstractmethod
  def process_error(self, error: str) -> tuple[str, str]:
    """
    Entry point of analyzing a single error entry. Returns the error message
    and auxiliary information that can help LLMs to fix the error.
    """

  @abstractmethod
  def group_errors(self, error_lines: list[str]) -> list[str]:
    """Groups multi-line error block into one string."""

  def get_header_for_func(self, func_name: str) -> str:
    """Get the header file location where the function was declared."""
    func_sig = introspector.query_introspector_function_signature(
        self.benchmark.project, func_name)
    return introspector.query_introspector_function_source_path(
        self.benchmark.project, func_sig)


class UnknownErrorAnalyzer(ErrorAnalyzer):
  """Minimum error analyzer for unknown format."""

  def group_errors(self, error_lines: list[str]) -> list[str]:
    """Keep error lines separated for unknown errors."""
    return error_lines

  def process_error(self, error: str) -> tuple[str, str]:
    """For unknown type of error, can't do anything just return."""
    return error, ''


class GNULinkerErrorAnalyzer(ErrorAnalyzer):
  """Analyzer for error messages produced by GNU ld."""
  # Matches: `fuzz.a(fuzz.o): desc:`
  # `(fuzz.o)` is optional.
  start_pattern = re.compile(r'([^\s:]+?)(?:\([^\s:]+?\))?: (.+):')

  # Matches: `fuzz.o:fuzz.cpp:(.text.func[func]+0x0): desc`
  # `fuzz.o:` is optional, `fuzz.cpp:` can also not present in some cases
  # (such as pre-compiled archive).
  sub_line_pattern = re.compile(
      r'([^\s:]+?:)?([^\s:]+?:)?\([^\s:]+?(\[[^\s:]+?\])?\+[^\s:]+?\): (.+)')

  # Error description patterns.
  in_func_pattern = re.compile(r'in function `(\S+?)\'')
  undef_ref_pattern = re.compile(r'undefined reference to `(\S+?)\'')
  multi_def_pattern = re.compile(r'multiple definition of `(\S+?)\'')

  def group_errors(self, error_lines: list[str]) -> list[str]:
    reformatted_lines = []
    dwarf_error = 'DWARF error: invalid or unhandled FORM value: 0x25'
    # Strip linker name, dwarf error and separate multiple linker errors on the
    # same line.
    for line in error_lines:
      line.replace(dwarf_error, '')
      reformatted_lines.extend(line.split('/usr/bin/ld: '))

    end_pattern = re.compile(
        r'clang.*: error: linker command failed with exit code 1 '
        r'\(use -v to see invocation\)')

    error_blocks = []
    curr_block = []
    for line in reformatted_lines:
      if not line:
        continue

      if ((self.start_pattern.fullmatch(line) or end_pattern.fullmatch(line))
          and curr_block):
        error_blocks.append('\n'.join(curr_block))
        curr_block = []

      curr_block.append(line)

    return error_blocks

  def resolve_undefined_reference(self,
                                  error_lines: list[str]) -> tuple[str, str]:
    """
    Simplify the error string and provide additional source info to resolve the
    error.
    """
    undef_ref_src = {}
    for line in error_lines[1:]:
      undef_ref_match = self.undef_ref_pattern.search(line)
      if not undef_ref_match:
        logging.warning('Cannot find undefined reference in: %s', line)
        continue
      ref_func = undef_ref_match.group(1)
      if ref_func in undef_ref_src:
        continue
      undef_ref_src[ref_func] = self.get_header_for_func(ref_func)

    in_func_match = self.in_func_pattern.search(error_lines[0])
    if in_func_match:
      origin_func = in_func_match.group(1)
    else:
      origin_func = ''
      logging.warning('Cannot find origin function in: %s', error_lines[0])
    short_error_msg = (f'In function <code>{origin_func}</code>: '
                       f'undefined reference to ')
    short_error_msg += ', '.join(
        f'<code>{func_name}</code>' for func_name in list(undef_ref_src.keys()))
    source_info = '\n'.join(f'<code>{func_name}</code> is defined at {src_loc}'
                            for func_name, src_loc in undef_ref_src)
    return short_error_msg, source_info

  def process_error(self, error: str) -> tuple[str, str]:
    """Process one error block and find context info if needed."""
    error_lines = error.split('\n')
    sub_line_match = self.sub_line_pattern.fullmatch(error_lines[1])
    if not sub_line_match:
      logging.warning('Unexpected sub line format: %s', error_lines[1])
      return error, ''
    error_desc = sub_line_match.group(4)

    if self.undef_ref_pattern.match(error_desc):
      return self.resolve_undefined_reference(error_lines)
    return error, ''


class LLVMLinkerErrorAnalyzer(ErrorAnalyzer):
  """Analyzer for error messages produced by LLVM lld."""

  def group_errors(self, error_lines: list[str]) -> list[str]:
    start_string = 'ld.lld: '
    sub_line_marker = '>>> '
    end_pattern = re.compile(
        r'clang.*: error: linker command failed with exit code 1 '
        r'\(use -v to see invocation\)')

    error_blocks = []
    curr_block = []
    for line in error_lines:
      if not line:
        continue

      if ((line.startswith(start_string) or end_pattern.fullmatch(line)) and
          curr_block):
        error_blocks.append('\n'.join(curr_block))
        curr_block = []

      # Remove start string and marker if presented.
      line = line.removeprefix(start_string)
      line = line.removeprefix(sub_line_marker)
      curr_block.append(line)

    return error_blocks

  def process_error(self, error: str) -> tuple[str, str]:
    return error, ''


class ClangDiagErrorAnalyzer(ErrorAnalyzer):
  """Analyzer for clang/++ diagnostic error messages."""
  # The following strings identify errors when the fuzz target is built with
  # clang and cannot be built with clang++, which should be removed.
  FALSE_FUZZED_DATA_PROVIDER_ERROR = ('include/fuzzer/FuzzedDataProvider.h:'
                                      '16:10:')
  FALSE_EXTERN_KEYWORD_ERROR = 'expected identifier or \'(\'\nextern "C"'

  def group_errors(self, error_lines: list[str]) -> list[str]:
    diag_pattern = re.compile(r'(\S*):\d+:\d+: (?!note).+: .+')
    include_pattern = re.compile(r'In file included from \S*:\d+:')
    end_pattern = re.compile(r'.*\d+ errors? generated.')

    error_blocks = []
    curr_block = []
    include_error_src_file = ''
    handling_include = False
    for line in error_lines:
      if not line:
        continue

      # Check if we are starting a new error block on this line.
      new_block = False
      # Handle a non note level diag line.
      diag_match = diag_pattern.match(line)
      if diag_match:
        err_src = diag_match.group(1)
        # Check if we are handling a diag line under a include error line.
        if handling_include:
          # Case when this is the first diag line after the include line.
          if not include_error_src_file:
            include_error_src_file = err_src
            continue
          # Case when there's more than one error in the same included file.
          if include_error_src_file == err_src:
            continue
          # Error source has changed, this is a new diag error block.
          include_error_src_file = ''
          handling_include = False
        new_block = True
      # Handle an include error line.
      # Start a new block if previously wasn't dealing with an include error,
      # or error source has been found for the previous include error.
      if (include_pattern.match(line) and
          (not handling_include or include_error_src_file)):
        include_error_src_file = ''
        handling_include = True
        new_block = True

      # Finished checking.
      if (new_block or end_pattern.match(line)) and curr_block:
        error_blocks.append('\n'.join(curr_block))
        curr_block = []
      curr_block.append(line)
    # The last clang diag line should always be the end pattern,
    # so the last valid curr_block has been handled.
    return error_blocks

  def process_error(self, error: str) -> tuple[str, str]:
    # Skip C only errors.
    # TODO(Dongge): Fix JCC to address this.
    # https://github.com/google/oss-fuzz-gen/pull/208/files/a0c0db2fd5860e6e4d434467c5ec9f949ee2cff1#r1571651507
    if (self.FALSE_EXTERN_KEYWORD_ERROR in error or
        self.FALSE_FUZZED_DATA_PROVIDER_ERROR in error):
      return '', ''
    return error, ''


def preprocess_error_messages(benchmark: Benchmark,
                              error_lines: list[str]) -> ErrorAnalyzer:
  """
  Groups multi-line error block into one string and return an ErrorAnalyzer
  for prompt building.
  """
  clang_pattern = re.compile(r'(\S*:\d+:\d+: .+: .+)|'
                             r'(In file included from \S*:\d+:)')
  gnu_ld_start_string = '/usr/bin/ld: '
  llvm_lld_start_string = 'ld.lld: '

  if not error_lines:
    return UnknownErrorAnalyzer(benchmark, error_lines)
  first_line = error_lines[0]
  if clang_pattern.fullmatch(first_line):
    return ClangDiagErrorAnalyzer(benchmark, error_lines)
  if first_line.startswith(gnu_ld_start_string):
    return GNULinkerErrorAnalyzer(benchmark, error_lines)
  if first_line.startswith(llvm_lld_start_string):
    return LLVMLinkerErrorAnalyzer(benchmark, error_lines)
  # Unknown error type, just return lines ungrouped.
  logging.warning('Unknown error: %s', '\n'.join(error_lines))  # debug
  return UnknownErrorAnalyzer(benchmark, error_lines)
