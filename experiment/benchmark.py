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
import sys
from enum import Enum
from typing import Any, List, Optional

import yaml


class FileType(Enum):
  """File types of target files."""
  C = 'C'
  CPP = 'C++'
  JAVA = 'Java'
  NONE = ''


# Define a custom representer for quoting strings
def quoted_string_presenter(dumper, data):
  if '\n' in data:
    return dumper.represent_scalar('tag:yaml.org,2002:str', data, style='|')
  return dumper.represent_scalar('tag:yaml.org,2002:str', data, style='"')


class Benchmark:
  """Represents a benchmark."""

  @classmethod
  def to_yaml(cls,
              benchmarks: list[Benchmark],
              outdir: str = './',
              out_basename: str = ''):
    """Converts and saves selected fields of a benchmark to a YAML file."""
    # Register the custom representer
    yaml.add_representer(str, quoted_string_presenter)
    result: dict[str, Any] = {
        'project': benchmarks[0].project,
        'language': benchmarks[0].language,
        'target_path': benchmarks[0].target_path,
        'target_name': benchmarks[0].target_name,
    }
    for benchmark in benchmarks:
      if benchmark.test_file_path:
        if 'test_files' not in result:
          result['test_files'] = []
        result['test_files'].append(
            {'test_file_path': benchmark.test_file_path})
      else:
        if 'functions' not in result:
          result['functions'] = []
        result['functions'].append({
            'signature': benchmark.function_signature,
            'name': benchmark.function_name,
            'return_type': benchmark.return_type,
            'params': benchmark.params
        })

    if not out_basename:
      out_basename = f'{benchmarks[0].project}.yaml'
    with open(os.path.join(outdir, out_basename), 'w') as file:
      yaml.dump(result, file, default_flow_style=False, width=sys.maxsize)

  @classmethod
  def from_yaml(cls, benchmark_path: str) -> List:
    """Constructs a benchmark based on a yaml file."""
    benchmarks = []
    with open(benchmark_path, 'r') as benchmark_file:
      data = yaml.safe_load(benchmark_file)
    if not data:
      return []

    project_name = data.get('project', '')
    use_context = data.get('use_context', False)
    use_project_examples = data.get('use_project_examples', True)
    cppify_headers = data.get('cppify_headers', False)
    commit = data.get('commit')
    functions = data.get('functions', [])

    test_files = data.get('test_files', [])
    if test_files:
      for test_file in test_files:
        max_len = os.pathconf('/', 'PC_NAME_MAX') - len('output-')
        test_file_path = test_file.get('test_file_path')
        normalized_test_path = test_file_path.replace('/', '_').replace(
            '.', '_').replace('-', '_')
        truncated_id = f'{project_name}-{normalized_test_path}'[:max_len]

        benchmarks.append(
            cls(
                truncated_id.lower(),
                data['project'],
                data['language'],
                '',
                '',
                '',
                [],
                data['target_path'],
                data.get('target_name', ''),
                test_file_path=test_file_path,
            ))

    if functions:
      # function type benchmark
      for function in functions:
        # Long raw_function_names (particularly for c++ projects) may exceed
        # filesystem limits on file path/name length when creating WorkDir.
        max_len = os.pathconf('/', 'PC_NAME_MAX') - len('output-')
        # Docker tag name cannot exceed 127 characters, and will be suffixed by
        # '<sample-id>-experiment'.
        docker_name_len = 127 - len('-03-experiment')
        max_len = min(max_len, docker_name_len)
        truncated_id = f'{project_name}-{function.get("name")}'[:max_len]
        benchmarks.append(
            cls(truncated_id.lower(),
                data['project'],
                data['language'],
                function.get('signature'),
                function.get('name'),
                function.get('return_type'),
                function.get('params'),
                data['target_path'],
                data.get('target_name'),
                use_project_examples=use_project_examples,
                cppify_headers=cppify_headers,
                commit=commit,
                use_context=use_context,
                function_dict=function))

    return benchmarks

  def __init__(self,
               benchmark_id: str,
               project: str,
               language: str,
               function_signature: str,
               function_name: str,
               return_type: str,
               params: list[dict[str, str]],
               target_path: str,
               preferred_target_name: Optional[str] = None,
               use_project_examples=True,
               cppify_headers=False,
               use_context=False,
               commit=None,
               function_dict: Optional[dict] = None,
               test_file_path: str = ''):
    self.id = benchmark_id
    self.project = project
    self.language = language
    self.function_signature = function_signature
    self.function_name = function_name
    self.return_type = return_type
    self.params = params
    self.function_dict = function_dict
    self.target_path = target_path
    self._preferred_target_name = preferred_target_name
    self.use_project_examples = use_project_examples
    self.use_context = use_context
    self.cppify_headers = cppify_headers
    self.commit = commit
    self.test_file_path = test_file_path

    if self.language == 'jvm':
      # For java projects, in order to differentiate between overloaded methods
      # the full signature is being used as function_name. The full signature
      # is following the format of:
      # [<Full_Class_Name].<Method_Name>(<Parameter_List>)
      # The benchmark id uses the function_signature directly and is used as
      # the name of the result directory. In order to avoid confusion in the
      # directory name remove special characters in the id coming from the
      # function signature. Additional special characters exist for
      # constructors which will be shown as <init> because constructors do not
      # have names.
      self.function_signature = self.function_name
      self.id = self.id.replace('<', '').replace('>', '')
      self.id = self.id.replace('[', '').replace(']', '')
      self.id = self.id.replace('(', '_').replace(')', '').replace(',', '_')

    if self.language == 'python':
      # For python projects, classes and methods name could begins with
      # underscore character. This could affect the benchmark_id and cause
      # OSS-Fuzz build failed if dot and underscore character is put together.
      # Special handling of benchmark_id is needed to avoid this situation.
      # For example, zipp._difference in zip project will have benchmark id of
      # zipp-zipp._difference and the pattern '._' cause OSS-Fuzz failed to
      # recognise the project name and needed to be replaced by
      # zipp-zipp.difference.
      self.id = self.id.replace('._', '.')

    if self.language = 'rust':
      # For rust projects, double colon (::) is sometime used to identify
      # crate, impl or trait name of a function. This could affect the
      # benchmark_id and cause OSS-Fuzz build failed.
      # Special handling of benchmark_id is needed to avoid this situation.
      self.id = self.id.replace('::', '-')

  def __str__(self):
    return (f'Benchmark<id={self.id}, project={self.project}, '
            f'language={self.language}, '
            f'function_signature={self.function_signature}, '
            f'function_name={self.function_name}, '
            f'return_type={self.return_type}, '
            f'params={self.params}, '
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

  @property
  def is_c_target(self) -> bool:
    """Validates if the project is written in C."""
    return self.file_type.value.lower() == 'c'

  @property
  def is_cpp_target(self) -> bool:
    """Validates if the project is written in C++."""
    return self.file_type.value.lower() == 'c++'

  @property
  def is_c_projcet(self) -> bool:
    """Validates if the project is written in C."""
    return self.language.lower() == 'c'

  @property
  def is_cpp_projcet(self) -> bool:
    """Validates if the project is written in C++."""
    return self.language.lower() == 'c++'

  @property
  def needs_extern(self) -> bool:
    """Checks if it is C++ fuzz target for a C project, which needs `extern`."""
    return self.is_cpp_target and self.is_c_projcet


def get_file_type(file_path: str) -> FileType:
  """Returns the file type based on the extension of |file_name|."""
  if file_path.endswith('.c'):
    return FileType.C
  cpp_extensions = ['.cc', '.cpp', '.cxx', '.c++', '.h', '.hpp']
  if any(file_path.endswith(ext) for ext in cpp_extensions):
    return FileType.CPP
  if file_path.endswith('.java'):
    return FileType.JAVA
  return FileType.NONE


def is_c_file(file_path: str) -> bool:
  """Validates if |file_path| is a C file by its extension."""
  return get_file_type(file_path) == FileType.C


def is_cpp_file(file_path: str) -> bool:
  """Validates if |file_path| is a C++ file by its extension."""
  return get_file_type(file_path) == FileType.CPP
