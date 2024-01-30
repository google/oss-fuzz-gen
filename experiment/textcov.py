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
from typing import List, Optional

# No spaces at t he beginning, and ends with a ":".
FUNCTION_PATTERN = re.compile(r'^[^\s](.+):$')
LINE_PATTERN = re.compile(r'^\s*\d+\|\s*([\d\.a-zA-Z]+)\|(.*)')


def demangle(data: str) -> str:
  """Demangle a string containing mangled C++ symbols."""
  return subprocess.check_output(['c++filt'], input=data, encoding='utf-8')


def normalize_template_args(name: str) -> str:
  """Normalize template arguments."""
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

  def subtract_covered_lines(self, other: Function):
    """Subtract covered lines."""

    # For our analysis purposes, we completely delete any lines that are
    # seen/covered by the other, rather than subtracting hitcounts.
    for line in other.lines.values():
      if line.contents in self.lines:
        del self.lines[line.contents]


@dataclasses.dataclass
class Textcov:
  """Textcov."""
  # Function name -> Function object.
  functions: dict[str, Function] = dataclasses.field(default_factory=dict)

  @classmethod
  def from_file(
      cls,
      file_handle,
      ignore_function_patterns: Optional[List[re.Pattern]] = None) -> Textcov:
    """Read a textcov from a file handle."""
    if ignore_function_patterns is None:
      ignore_function_patterns = []

    textcov = cls()

    current_function_name: str = ''
    current_function: Function = Function()
    demangled = demangle(file_handle.read())
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
        self.functions[function.name].subtract_covered_lines(function)

  @property
  def covered_lines(self):
    return sum(f.covered_lines for f in self.functions.values())
