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
    self.errors = errors

  def __eq__(self, other):
    if not issubclass(type(other), ErrorAnalyzer):
      return False
    return self.errors == other.errors

  def __bool__(self):
    return bool(self.errors)

  @abstractmethod
  def process_error(self, error: str) -> tuple[str, str]:
    """
    Entry point of analyzing a single error entry. Returns the error message
    and auxiliary information that can help LLMs to fix the error.
    """

  def get_header_for_func(self, func_name: str) -> str:
    """Get the header file location where the function was declared."""
    func_sig = introspector.query_introspector_function_signature(
        self.benchmark.project, func_name)
    return introspector.query_introspector_function_source_path(
        self.benchmark.project, func_sig)


class UnknownErrorAnalyzer(ErrorAnalyzer):
  """Minimum error analyzer for unknown format."""

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

  def process_error(self, error: str) -> tuple[str, str]:
    return error, ''


class ClangDiagErrorAnalyzer(ErrorAnalyzer):
  """Analyzer for clang/++ diagnostic error messages."""
  # The following strings identify errors when the fuzz target is built with
  # clang and cannot be built with clang++, which should be removed.
  FALSE_FUZZED_DATA_PROVIDER_ERROR = ('include/fuzzer/FuzzedDataProvider.h:'
                                      '16:10:')
  FALSE_EXTERN_KEYWORD_ERROR = 'expected identifier or \'(\'\nextern "C"'

  def process_error(self, error: str) -> tuple[str, str]:
    # Skip C only errors.
    # TODO(Dongge): Fix JCC to address this.
    # https://github.com/google/oss-fuzz-gen/pull/208/files/a0c0db2fd5860e6e4d434467c5ec9f949ee2cff1#r1571651507
    if (self.FALSE_EXTERN_KEYWORD_ERROR in error or
        self.FALSE_FUZZED_DATA_PROVIDER_ERROR in error):
      return '', ''
    return error, ''
