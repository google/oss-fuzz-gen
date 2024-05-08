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
"""Textcov parsing and analysis."""

from __future__ import annotations

import dataclasses
import re
import subprocess
import xml.etree.ElementTree as ET
from typing import List, Optional

# No spaces at the beginning, and ends with a ":".
FUNCTION_PATTERN = re.compile(r'^([^\s].*):$')
LINE_PATTERN = re.compile(r'^\s*\d+\|\s*([\d\.a-zA-Z]+)\|(.*)')

JVM_CLASS_MAPPING = {
    'Z': 'boolean',
    'B': 'byte',
    'C': 'char',
    'D': 'double',
    'F': 'float',
    'I': 'int',
    'J': 'long',
    'S': 'short'
}

JVM_SKIPPED_METHOD = [
    '<init>', '<cinit>', 'fuzzerTestOneInput', 'fuzzerInitialize',
    'fuzzerTearDown'
]


def demangle(data: str) -> str:
  """Demangles a string containing mangled C++ symbols."""
  return subprocess.check_output(['c++filt'], input=data, encoding='utf-8')


def _discard_fuzz_target_lines(covreport_content: str) -> str:
  """Removes fuzz target lines from the coverage report."""
  # When comparing project code coverage contributed by fuzz targets, it's
  # fairer to only consider lines in the project and not the code of targets.
  # Assumption 1: llvm-cov separates lines from different files with an empty
  # line by default in the coverage report.
  # Assumption 2: All and only fuzz targets contain 'LLVMFuzzerTestOneInput'.
  project_file_contents = [
      sec for sec in covreport_content.split('\n\n')
      if 'LLVMFuzzerTestOneInput' not in sec
  ]
  return '\n\n'.join(project_file_contents)


def normalize_template_args(name: str) -> str:
  """Normalizes template arguments."""
  return re.sub(r'<.*>', '<>', name)


def _parse_hitcount(data: str) -> float:
  """Parse a hitcount."""
  # From https://github.com/llvm/llvm-project/blob/3f3620e5c9ee0f7b64afc39e5a26c6f4cc5e7b37/llvm/tools/llvm-cov/SourceCoverageView.cpp#L102
  multipliers = {
      'k': 1000,
      'M': 1000000,
      'G': 1000000000,
      'T': 1000000000000,
      'P': 1000000000000000,
      'E': 1000000000000000000,
      'Z': 1000000000000000000000,
      'Y': 1000000000000000000000000,
  }

  if data[-1].isdigit():
    # Simple number < 1000.
    return int(data)

  if data[-1] in multipliers:
    # E.g. "11.4k"
    return float(data[:-1]) * multipliers[data[-1]]

  raise ValueError(f'Suffix {data[-1]} is not supported')


@dataclasses.dataclass
class Line:
  """Represents a line."""
  contents: str = ''
  hit_count: float = 0


@dataclasses.dataclass
class Function:
  """Represents a function in a textcov."""
  name: str = ''
  # Line contents -> Line object. We key on line contents to account for
  # potential line number movements.
  lines: dict[str, Line] = dataclasses.field(default_factory=dict)

  def merge(self, other: Function):
    for line in other.lines.values():
      if line.contents in self.lines:
        self.lines[line.contents].hit_count += line.hit_count
      else:
        self.lines[line.contents] = Line(contents=line.contents,
                                         hit_count=line.hit_count)

  @property
  def covered_lines(self):
    return sum(1 for l in self.lines.values() if l.hit_count > 0)

  def subtract_covered_lines(self, other: Function, language: str = 'c++'):
    """Subtract covered lines."""

    if language == 'jvm':
      total_line = len(self.lines)
      self.lines = {}
      new_covered_lines = other.covered_lines - self.covered_lines
      for i in range(total_line):
        line = f'Line{i}'
        if i >= new_covered_lines:
          self.lines[line] = Line(contents=line, hit_count=0)
        else:
          self.lines[line] = Line(contents=line, hit_count=1)
    else:
      # For our analysis purposes, we completely delete any lines that are
      # hit by the other, rather than subtracting hitcounts.
      for line in other.lines.values():
        if line.hit_count and line.contents in self.lines:
          del self.lines[line.contents]


@dataclasses.dataclass
class Textcov:
  """Textcov."""
  # Function name -> Function object.
  functions: dict[str, Function] = dataclasses.field(default_factory=dict)
  language: str = 'c++'

  @classmethod
  def from_file(
      cls,
      file_handle,
      ignore_function_patterns: Optional[List[re.Pattern]] = None) -> Textcov:
    """Read a textcov from a file handle."""
    if ignore_function_patterns is None:
      ignore_function_patterns = []

    textcov = cls()
    textcov.language = 'c++'

    current_function_name: str = ''
    current_function: Function = Function()
    demangled = demangle(file_handle.read())
    demangled = _discard_fuzz_target_lines(demangled)

    for line in demangled.split('\n'):
      match = FUNCTION_PATTERN.match(line)
      if match:
        # Normalize templates.
        current_function_name = normalize_template_args(match.group(1))
        if any(
            p.match(current_function_name) for p in ignore_function_patterns):
          # Ignore this function.
          current_function_name = ''
          continue

        if current_function_name in textcov.functions:
          current_function = textcov.functions[current_function_name]
        else:
          current_function = Function(name=current_function_name)
          textcov.functions[current_function_name] = current_function

        continue

      if not current_function_name:
        # No current functions. This can happen if we're currently in an
        # ignored function.
        continue

      match = LINE_PATTERN.match(line)
      if match:
        hit_count = _parse_hitcount(match.group(1))
        # Ignore whitespace differences
        line_contents = match.group(2).strip()

        if line_contents in current_function.lines:
          current_function.lines[line_contents].hit_count += hit_count
        else:
          current_function.lines[line_contents] = Line(contents=line_contents,
                                                       hit_count=hit_count)

        continue
    return textcov

  @classmethod
  def from_jvm_file(cls, file_path) -> Textcov:
    """Read a textcov from a jacoco.xml path."""
    textcov = cls()
    textcov.language = 'jvm'
    jacoco_report = ET.parse(file_path)

    class_method_items = []
    for item in jacoco_report.iter():
      if item.tag == 'class':
        # Get class name and skip fuzzing and testing classes
        class_name = item.attrib['name'].replace('/', '.')
        if 'test' in class_name.lower() or 'fuzzer' in class_name.lower():
          continue

        for method_item in item:
          if method_item.tag == 'method':
            if method_item.attrib['name'] not in JVM_SKIPPED_METHOD:
              class_method_items.append((class_name, method_item))

    for class_name, method_item in class_method_items:
      method_dict = method_item.attrib
      method_name = method_dict['name']

      # Process all arguments type from shortern Java Class naming
      args = textcov.determine_jvm_arguments_type(method_dict['desc'])

      # Save method
      full_method_name = f'[{class_name}].{method_name}({",".join(args)})'
      current_method = Function(name=full_method_name)

      # Retrieve line coverage information
      total_line = 0
      covered_line = 0
      for cov_data in method_item:
        if cov_data.attrib['type'] == 'LINE':
          covered_line = int(cov_data.attrib['covered'])
          total_line = int(cov_data.attrib['covered']) + int(
              cov_data.attrib['missed'])
      for i in range(total_line):
        line = f'Line{i}'
        if i >= covered_line:
          current_method.lines[line] = Line(contents=line, hit_count=0)
        else:
          current_method.lines[line] = Line(contents=line, hit_count=1)

      textcov.functions[full_method_name] = current_method

    return textcov

  def to_file(self, filename: str) -> None:
    """Writes covered functions and lines to |filename|."""
    file_content = ''
    for func_obj in self.functions.values():
      for line_content, line_obj in func_obj.lines.items():
        file_content += f'{line_content}\n' if line_obj.hit_count else ''

    with open(filename, 'w') as file:
      file.write(file_content)

  def merge(self, other: Textcov):
    """Merge another textcov"""
    for function in other.functions.values():
      if function.name not in self.functions:
        self.functions[function.name] = Function(name=function.name)
      self.functions[function.name].merge(function)

  def subtract_covered_lines(self, other: Textcov):
    """Diff another textcov"""
    for function in other.functions.values():
      if function.name in self.functions:
        self.functions[function.name].subtract_covered_lines(
            function, self.language)

  @property
  def covered_lines(self):
    return sum(f.covered_lines for f in self.functions.values())

  def determine_jvm_arguments_type(self, desc: str) -> List[str]:
    """Determine list of jvm arguments type"""
    args = []
    arg = ''
    start = False
    for c in desc:
      if c == '(':
        continue
      if c == ')':
        break

      if start:
        if c == ';':
          start = False
          args.append(arg.replace('/', '.'))
        else:
          arg = arg + c
      else:
        if c == 'L':
          start = True
          arg = ''
        else:
          if c in JVM_CLASS_MAPPING:
            args.append(JVM_CLASS_MAPPING[c])

    return args
