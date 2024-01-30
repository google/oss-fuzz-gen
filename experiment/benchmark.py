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
Benchmark class that contains the project-under-test information.
"""
from __future__ import annotations

import os
import re
import traceback
from enum import Enum
from typing import List, Optional

import yaml


class FileType(Enum):
  """File types of target files."""
  C = 'C'
  CPP = 'C++'
  NONE = ''


def parse_function_name(function_signature: str) -> str:
  """Parses the function name from the function signature."""
  # Invalid matches:
  # 1. __attribute__((.*))
  # 2. __attribute__((alloc_size(1)))
  names = re.findall(r'.*?\s*([\w:<>+*~]+)\s*\([^\(]*\)', function_signature)
  if names:
    # Normalize names.
    return re.sub(r'[^\w:]', '-', names[-1])

  raise ValueError('Invalid function signature: ' + function_signature)


def function_name_regex(function_name, include_top_level=False) -> str:
  """The regex to capture function name"""
  # TODO: Temp workaround for issue #27, allows fuzzy match for special chars
  #  to be removed when we have feature from FI to properly fix this.
  # function<type~> -> function[^\w:]type[^\w:][^\w:]
  function_name = re.sub(r'[^\w:]', '[^\\\\w:]', function_name)
  parts = function_name.split('::')
  if len(parts) < 2:
    return function_name

  options = []
  # a::b::c ->
  #  [b::c, a::b::c]
  # We don't do just "c" by default,
  # because it's too generic and results in false positives.
  if include_top_level:
    # Also include "c"
    start = 1
  else:
    start = 2
  for i in range(len(parts) - start, -1, -1):
    options.append('::'.join(parts[i:]))

  return '(' + '|'.join(options) + ')'


class Benchmark:
  """Represents a benchmark."""

  @classmethod
  def to_yaml(cls, benchmarks: list[Benchmark]) -> str:
    result = {
        'project': benchmarks[0].project,
        'target_path': benchmarks[0].target_path,
        'target_name': benchmarks[0].target_name,
        'functions': [b.function_signature for b in benchmarks],
    }

    return yaml.dump(result)

  @classmethod
  def from_yaml(cls, benchmark_path: str) -> List:
    """Constructs a benchmark based on a yaml file."""
    benchmarks = []
    with open(benchmark_path, 'r') as benchmark_file:
      data = yaml.safe_load(benchmark_file)

    benchmark_name = os.path.splitext(os.path.basename(benchmark_path))[0]

    use_context = data.get('use_context', False)
    use_project_examples = data.get('use_project_examples', True)
    cppify_headers = data.get('cppify_headers', False)
    commit = data.get('commit')
    functions = data.get('functions', [])
    for function_signature in functions:
      try:
        function_name = parse_function_name(function_signature)
      except ValueError:
        print(f'WARNING: Invalid benchmark config: {benchmark_path}')
        traceback.print_exc()
        continue

      # Prevent ':' from causing issues as it propagates to other places.
      function_name = function_name.replace('::', '-')
      benchmarks.append(
          cls(f'{benchmark_name}-{function_name}'.lower(),
              data['project'],
              function_signature,
              data['target_path'],
              data.get('target_name'),
              use_project_examples=use_project_examples,
              cppify_headers=cppify_headers,
              commit=commit,
              use_context=use_context))

    return benchmarks

  def __init__(self,
               benchmark_id: Optional[str],
               project: str,
               function_signature: str,
               target_path: str,
               preferred_target_name: Optional[str] = None,
               use_project_examples=True,
               cppify_headers=False,
               use_context=False,
               commit=None,
               function_dict: Optional[dict] = None):
    self.id = benchmark_id
    self.project = project
    self.function_signature = function_signature
    # TODO(dongge): Refactor Benchmark YAML so that it stores functions as
    # dictionaries instead of strings.
    # Added this a temporary mitigation for parsing failure.
    if function_dict:
      self.function_name = function_dict.get('function_name', '')
    else:
      self.function_name = parse_function_name(function_signature)

    if not self.id:
      # Prevent ':' from causing issues as it propagates to other places.
      function_name = self.function_name.replace('::', '-')
      self.id = f'{self.project}-{function_name}'.lower()

    self.target_path = target_path
    self._preferred_target_name = preferred_target_name
    self.use_project_examples = use_project_examples
    self.use_context = use_context
    self.cppify_headers = cppify_headers
    self.commit = commit

  def __str__(self):
    return (f'Benchmark<id={self.id}, project={self.project}, '
            f'function_signature={self.function_signature}, '
            f'target_path={self.target_path}, '
            f'target_name={self.target_name}, '
            f'use_context={self.use_context}>')

  @property
  def target_name(self):
    """Returns target_name if it is defined,
        otherwise use the basename of the target path."""
    return (self._preferred_target_name or
            os.path.splitext(os.path.basename(self.target_path))[0])

  @property
  def file_type(self) -> FileType:
    """Returns the file type of the benchmark."""
    return get_file_type(self.target_path)


def get_file_type(file_path: str) -> FileType:
  """Returns the file type based on the extension of |file_name|."""
  if file_path.endswith('.c'):
    return FileType.C
  cpp_extensions = ['.cc', '.cpp', '.cxx', '.c++', '.h', '.hpp']
  if any(file_path.endswith(ext) for ext in cpp_extensions):
    return FileType.CPP
  return FileType.NONE


def is_c_file(file_path: str) -> bool:
  """Validates if |file_path| is a C file by its extension."""
  return get_file_type(file_path) == FileType.C


def is_cpp_file(file_path: str) -> bool:
  """Validates if |file_path| is a C++ file by its extension."""
  return get_file_type(file_path) == FileType.CPP
