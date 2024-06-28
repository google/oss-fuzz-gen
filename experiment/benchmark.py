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
from typing import List, Optional

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
  def to_yaml(cls, benchmarks: list[Benchmark], outdir: str = './'):
    """Converts and saves selected fields of a benchmark to a YAML file."""
    # Register the custom representer
    yaml.add_representer(str, quoted_string_presenter)
    result = {
        'project':
            benchmarks[0].project,
        'language':
            benchmarks[0].language,
        'target_path':
            benchmarks[0].target_path,
        'target_name':
            benchmarks[0].target_name,
        'functions': [{
            'signature': b.function_signature,
            'name': b.function_name,
            'return_type': b.return_type,
            'params': b.params,
        } for b in benchmarks],
    }
    with open(os.path.join(outdir, f'{benchmarks[0].project}.yaml'),
              'w') as file:
      yaml.dump(result, file, default_flow_style=False, width=sys.maxsize)

  @classmethod
  def from_yaml(cls, benchmark_path: str) -> List:
    """Constructs a benchmark based on a yaml file."""
    benchmarks = []
    with open(benchmark_path, 'r') as benchmark_file:
      data = yaml.safe_load(benchmark_file)

    project_name = os.path.splitext(os.path.basename(benchmark_path))[0]

    use_context = data.get('use_context', False)
    use_project_examples = data.get('use_project_examples', True)
    cppify_headers = data.get('cppify_headers', False)
    commit = data.get('commit')
    functions = data.get('functions', [])
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
              use_context=use_context))

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
               function_dict: Optional[dict] = None):
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

    if self.language == 'jvm':
      # For java project, in order to differentiate between overloaded methos,
      # the full signature is being used as function_name. The full signature
      # is following the format of
      # [<Full_Class_Name].<Method_Name>(<Parameter_List>)
      # The benchmark id uses the function_signature directly and used as the
      # name of the result directory. To avoid confusion in the directory name,
      # these special characters in the id (coming from the function signature)
      # are removed. Additional special characters exist for constructors which
      # will shown as <init> because constructors does not have names.
      self.function_signature = self.function_name
      self.id = self.id.replace('<', '').replace('>', '')
      self.id = self.id.replace('[', '').replace(']', '')
      self.id = self.id.replace('(', '_').replace(')', '').replace(',', '_')

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
  def needs_extern(self) -> bool:
    """Checks if it is C++ fuzz target for a C project, which needs `extern`."""
    return (self.file_type.value.lower() == 'c++' and
            self.language.lower() == 'c')


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
