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
"""Provides a set of utils for oss-fuzz-gen on new Java projects integration"""

import logging
import os
import shutil
import subprocess
from typing import Optional

from urllib3.util import parse_url

from auto_build.jvm import oss_fuzz_templates
from experiment import benchmark as benchmarklib

logger = logging.getLogger(__name__)


# Project preparation utils
###########################
def git_clone_project(github_url: str, destination: str) -> bool:
  """Clone project from github url to destination"""
  cmd = ['git clone', github_url, destination]
  try:
    subprocess.check_call(" ".join(cmd),
                          shell=True,
                          timeout=600,
                          stdout=subprocess.DEVNULL,
                          stderr=subprocess.DEVNULL)
  except subprocess.TimeoutExpired:
    return False
  except subprocess.CalledProcessError:
    return False
  return True


def get_project_name(github_url: str) -> Optional[str]:
  """Get project name by simplify github url"""
  # HTTPS Type
  # https://github.com/{user}/{proj_name} or https://github.com/{user}/{proj_name}.git
  # or
  # SSH Type
  # git@github.com:{user}/{proj_name} or git@github.com:{user}/{proj_name}.git

  # Remove the .git suffix
  if github_url.endswith('.git'):
    github_url = github_url[:-4]

  if github_url.startswith('https://'):
    # Validate url for HTTPS type
    parsed_url = parse_url(github_url)
    host = parsed_url.host
    path = parsed_url.path
    if path and host == 'github.com' and len(path.split('/')) == 3:
      return path.split('/')[2]
  elif github_url.startswith('git@github.com:'):
    # Validate url for SSH type
    path = github_url.split('/')
    if len(path) == 2:
      return path[1]

  # Malformed or invalid github url
  return None


def prepare_base_files(base_dir: str, project_name: str, url: str) -> bool:
  """Prepare OSS-Fuzz base files for Java project fuzzing"""
  build_file = _get_build_file(base_dir, project_name, True)
  if not build_file:
    return False

  try:
    with open(os.path.join(base_dir, 'build.sh'), 'w') as f:
      f.write(build_file)

    with open(os.path.join(base_dir, 'Dockerfile'), 'w') as f:
      f.write(oss_fuzz_templates.DOCKERFILE_JAVA.replace("TARGET_REPO", url))

    with open(os.path.join(base_dir, 'project.yaml'), 'w') as f:
      f.write(oss_fuzz_templates.YAML_JAVA.replace("TARGET_REPO", url))

    with open(os.path.join(base_dir, 'Fuzz.java'), 'w') as f:
      f.write(oss_fuzz_templates.FUZZER_JAVA)
  except:
    return False

  return True


def get_next_project_dir(oss_fuzz_dir) -> str:
  """Prepare the OSS-Fuzz project directory for static analysis"""
  project_dir = os.path.join(oss_fuzz_dir, 'projects')
  auto_gen = 'java-autofuzz-dir-'
  max_idx = -1
  for l in os.listdir(project_dir):
    if l.startswith(auto_gen):
      tmp_dir_idx = int(l.replace(auto_gen, ''))
      max_idx = max(max_idx, tmp_dir_idx)
  return os.path.join(project_dir, f'{auto_gen}{max_idx + 1}')


def _get_build_file(base_dir: str, project_name: str,
                    is_introspector: bool) -> str:
  """Prepare build.sh content for this project."""

  build_type = _find_project_build_type(os.path.join(base_dir, "proj"),
                                        project_name)

  if build_type == 'ant':
    build_file = oss_fuzz_templates.BUILD_JAVA_ANT
  elif build_type == 'gradle':
    build_file = oss_fuzz_templates.BUILD_JAVA_GRADLE
  elif build_type == 'maven':
    build_file = oss_fuzz_templates.BUILD_JAVA_MAVEN
  else:
    return ''

  build_file = build_file + oss_fuzz_templates.BUILD_JAVA_BASE

  if is_introspector:
    return build_file + oss_fuzz_templates.BUILD_JAVA_INTROSPECTOR

  return build_file


# Java Project discovery utils
##############################
def _find_dir_build_type(project_dir: str) -> str:
  """Determine the java build project type of the directory"""

  if os.path.exists(os.path.join(project_dir, 'pom.xml')):
    return 'maven'

  if os.path.exists(os.path.join(
      project_dir, 'build.gradle')) or os.path.exists(
          os.path.join(project_dir, 'build.gradle.kts')):
    return 'gradle'

  if os.path.exists(os.path.join(project_dir, 'build.xml')):
    return 'ant'

  return ''


def _find_project_build_type(project_dir: str, proj_name: str) -> str:
  """Search for base project directory to detect project build type"""
  # Search for current directory first
  project_build_type = _find_dir_build_type(project_dir)
  if project_build_type:
    return project_build_type

  # Search for sub directory with name same as project name
  for subdir in os.listdir(project_dir):
    if os.path.isdir(os.path.join(project_dir, subdir)) and subdir == proj_name:
      project_build_type = _find_dir_build_type(
          os.path.join(project_dir, subdir))
    if project_build_type:
      return project_build_type

  # Recursively look for subdirectory that contains build property file
  for root, _, _ in os.walk(project_dir):
    project_build_type = _find_dir_build_type(root)
    if project_build_type:
      return project_build_type

  return ''


def _is_class_in_project(project_dir: str, class_name: str) -> bool:
  """Find if the given class name is in the project"""
  class_path = class_name.replace(".", "/")
  command = f'find {project_dir} -wholename */{class_path}.java'

  try:
    if not subprocess.check_output(
        command, shell=True, stderr=subprocess.DEVNULL):
      return False
  except subprocess.CalledProcessError:
    return False

  return True


# Method candidates sorting and filtering utils
###############################################
def is_exclude_method(project_dir: str, function: dict) -> bool:
  """Check if the method match any of the following criteria and should be
  excluded.
  1) The method is not belongs to the target project
  2) The method contains specific excluded name
  3) The method is not public
  4) The method is not concrete
  5) The method is belongs to the base JDK library
  6) The method has 0 arguments"""

  excluded_function_name = [
      'fuzzertestoneinput', 'fuzzerinitialize', 'fuzzerteardown', 'exception',
      'error', 'test'
  ]

  method_name = function.get('functionName', '')
  class_name = function.get('functionSourceFile', '').split('$')[0]
  method_info = function.get('JavaMethodInfo', {})
  is_public = method_info.get('public', True) and method_info.get(
      'classPublic', True)
  is_concrete = method_info.get('concrete', True) and method_info.get(
      'classConcrete', True)
  is_java_lib = method_info.get('javaLibraryMethod', True)
  arg_count = function.get('argCount', 0)

  return not _is_class_in_project(project_dir, class_name) or any(
      name in method_name.lower() for name in excluded_function_name
  ) or not is_public or not is_concrete or is_java_lib or arg_count <= 0


def sort_methods_by_fuzz_worthiness(functions: list[dict]) -> list[dict]:
  """Sort the function list according to the following criteria in order.
    The order is acscending unless otherwise specified.
    For boolean sorting, False is always in front of True in acscending order.
    1) If the function belongs to a enum class.
    2) The function call depth in descending order.
    3) The cyclomatic complexity of the function in descending order.
    4) The number of arguments of this function in descending order.
    5) Number of source code lines in descending order."""

  return sorted(functions,
                key=lambda item:
                (item.get('JavaMethodInfo', {}).get('classEnum', False),
                 -item.get('functionDepth', 0), -item.get(
                     'CyclomaticComplexity', 0), -item.get('argCount', 0), -max(
                         0,
                         item.get('functionLinenumberEnd', 0) - item.get(
                             'functionLinenumber', 0))),
                reverse=False)


def group_functions_by_return_type(functions: list[dict]) -> dict[str, dict]:
  """Group functions by return type and its constructors/builders status."""

  excluded_return_type = [
      'byte', 'boolean', 'char', 'int', 'long', 'short', 'double', 'float',
      'void', 'java.lang.Byte', 'java.lang.Short', 'java.lang.Integer',
      'java.lang.Long', 'java.lang.Float', 'java.lang.Double',
      'java.lang.Character', 'java.lang.Boolean', 'java.lang.String'
  ]

  functions_group_by_return_type = {}
  for function in functions:
    function_name = function.get('functionName', '')
    return_type = function.get('returnType', '')
    method_info = function.get('JavaMethodInfo', {})

    # Preprocess constructor return types
    if '<init>' in function_name:
      return_type = function.get('functionSourceFile', '').split('$')[0]

    # Skip methods with excluded return type
    if not return_type or return_type in excluded_return_type:
      continue

    # Skip inaccessible methods
    is_public = method_info.get('public', True) and method_info.get(
        'classPublic', True)
    is_concrete = method_info.get('concrete', True) and method_info.get(
        'classConcrete', True)
    is_java_lib = method_info.get('javaLibraryMethod', True)
    if not is_public or not is_concrete or is_java_lib:
      continue

    return_type_group = functions_group_by_return_type.get(return_type, {})
    function_dict = {
        'function_signature': function_name,
        'is_static': method_info.get('static', False),
        'exceptions': method_info.get('exceptions', []),
        'need-close': method_info.get('need-close', False)
    }

    if '<init>' in function_name:
      constructors = return_type_group.get('constructors', [])
      constructors.append(function_dict)
      return_type_group['constructors'] = constructors
    else:
      builders = return_type_group.get('builders', [])
      builders.append(function_dict)
      return_type_group['buidlers'] = builders

    functions_group_by_return_type[return_type] = return_type_group

  return functions_group_by_return_type


# Benchmark generation utils
############################
def generate_benchmarks_from_github_url(oss_fuzz_dir: str, benchmark_dir: str,
                                        url: str) -> Optional[str]:
  """This function generate benchmark yaml for the given project url."""

  project_name = get_project_name(url)
  if not project_name:
    # Invalid url
    logger.warning(f'Skipping wrong github url: {url}')
    return None

  # Clone project for static analysis
  base_dir = get_next_project_dir(oss_fuzz_dir)
  project_dir = os.path.join(base_dir, 'proj')
  if not git_clone_project(url, project_dir):
    # Invalid url
    logger.warning(f'Failed to clone from the github url: {url}')
    shutil.rmtree(base_dir)
    return None

  # Prepare OSS-Fuzz base files
  if not prepare_base_files(base_dir, project_name, url):
    # Invalid build type or non-Java project
    logger.warning(f'Build type of project {project_name} is not supported.')
    shutil.rmtree(base_dir)
    return None

  # Run OSS-Fuzz build and static analysis on the project
  data_yaml_path = run_oss_fuzz_build(os.path.basename(base_dir), oss_fuzz_dir)
  if not data_yaml_path:
    # Failed to build or run static analysis on the project
    logger.warning(f'Failed to build project {project_name} with JDK15.')
    shutil.rmtree(base_dir)
    return None

  # Save data.yaml from static analysis as benchmark files
  benchmarks = benchmarklib.Benchmark.from_java_data_yaml(
      data_yaml_path, project_name, project_dir, os.path.basename(base_dir))
  if benchmarks:
    benchmarklib.Benchmark.to_yaml(benchmarks, benchmark_dir)

  # Clean up the working directory and remove introspector code from build.sh
  with open(os.path.join(base_dir, 'build.sh'), 'w') as f:
    f.write(_get_build_file(base_dir, project_name, False))
  shutil.rmtree(project_dir)

  return base_dir


# OSS-Fuzz project utils
########################
def run_oss_fuzz_build(project_name: str, oss_fuzz_dir: str) -> Optional[str]:
  """Build the project with OSS-Fuzz commands and returns path of
  fuzzerLogFile-Fuzz.data.yaml from static analysis"""

  cmd = f'python3 infra/helper.py build_fuzzers {project_name}'
  try:
    subprocess.check_call(cmd,
                          shell=True,
                          cwd=oss_fuzz_dir,
                          stdout=subprocess.DEVNULL,
                          stderr=subprocess.DEVNULL)
  except subprocess.CalledProcessError:
    return None

  # Locate the static analysis report
  data_yaml_path = os.path.join(oss_fuzz_dir, 'build', 'out', project_name,
                                'fuzzerLogFile-Fuzz.data.yaml')

  if os.path.isfile(data_yaml_path):
    return data_yaml_path

  return None
