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
###############################################################################
"""Provides a set of utils for oss-fuzz-gen on new Java projects integration"""

import logging
import os
import subprocess
from typing import Optional

import constants
import oss_fuzz_templates
from urllib3.util import parse_url

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

  # Determine build type and build directory for the project
  build_type, version = _find_project_build_type(os.path.join(base_dir, "proj"),
                                                 project_name)

  # Preapre build.sh and Dockerfile
  build_file = _get_build_file(build_type)
  docker_file = _get_docker_file(build_type, version, url)
  if not docker_file or not build_file:
    return False

  try:
    with open(os.path.join(base_dir, 'build.sh'), 'w') as f:
      f.write(build_file)

    with open(os.path.join(base_dir, 'Dockerfile'), 'w') as f:
      f.write(docker_file)

    with open(os.path.join(base_dir, 'project.yaml'), 'w') as f:
      f.write(oss_fuzz_templates.YAML_JAVA.replace("{TARGET_REPO}", url))

    with open(os.path.join(base_dir, 'Fuzz.java'), 'w') as f:
      f.write(oss_fuzz_templates.FUZZER_JAVA)
  except:
    return False

  return True


def _get_build_file(build_type: str) -> str:
  """Prepare build.sh content for this project."""

  if build_type == 'ant':
    build_file = oss_fuzz_templates.BUILD_JAVA_ANT
  elif build_type == 'gradle':
    build_file = oss_fuzz_templates.BUILD_JAVA_GRADLE
  elif build_type == 'maven':
    build_file = oss_fuzz_templates.BUILD_JAVA_MAVEN
  else:
    return ''

  return build_file + oss_fuzz_templates.BUILD_JAVA_BASE


def _get_docker_file(build_type: str, version: str, url: str) -> str:
  """Prepare build.sh content for this project."""

  if build_type == 'ant':
    docker_file = oss_fuzz_templates.DOCKERFILE_JAVA_ANT
    docker_file = docker_file.replace('{ANT_URL}', constants.ANT_URL)
  elif build_type == 'gradle':
    docker_file = oss_fuzz_templates.DOCKERFILE_JAVA_GRADLE
    docker_file = docker_file.replace('{GRADLE_URL}', constants.GRADLE_URL)
  elif build_type == 'maven':
    # Check for invalid version
    if version not in constants.MAVEN_URL:
      return ''

    docker_file = oss_fuzz_templates.DOCKERFILE_JAVA_MAVEN
    docker_file = docker_file.replace('{MAVEN_URL}',
                                      constants.MAVEN_URL[version])
    docker_file = docker_file.replace('{MAVEN_VERSION}', version)
  else:
    return ''

  docker_file = docker_file.replace('{PROTO_URL}', constants.PROTO_URL)
  docker_file = docker_file.replace('{JDK15_URL}', constants.JDK15_URL)
  docker_file = docker_file.replace('{TARGET_REPO}', url)

  return docker_file


# Java Project discovery utils
##############################
def _find_dir_build_type(project_dir: str) -> tuple[str, str]:
  """Determine the java build project type of the directory"""

  if os.path.exists(os.path.join(project_dir, 'pom.xml')):
    return 'maven', _get_maven_version(project_dir)

  if os.path.exists(os.path.join(
      project_dir, 'build.gradle')) or os.path.exists(
          os.path.join(project_dir, 'build.gradle.kts')):
    return 'gradle', ''

  if os.path.exists(os.path.join(project_dir, 'build.xml')):
    return 'ant', ''

  return ''


def _get_maven_version(base_dir: str) -> str:
  """Prepare Maven specific logic for build.sh."""
  with open(os.path.join(base_dir, 'pom.xml'), 'r') as f:
    data = f.read()

  # Determine if the project requires older JVM
  if '<source>1.5</source>' in data or '<target>1.5</target>' in data:
    return '3.1.1'

  if '<source>1.6</source>' in data or '<target>1.6</target>' in data:
    return '3.2.5'

  return '3.9.2'


def _find_project_build_type(project_dir: str,
                             proj_name: str) -> tuple[str, str]:
  """Search for base project directory to detect project build type"""
  # Search for current directory first
  project_build_data = _find_dir_build_type(project_dir)
  if project_build_data:
    return project_build_data

  # Search for sub directory with name same as project name
  for subdir in os.listdir(project_dir):
    if os.path.isdir(os.path.join(project_dir, subdir)) and subdir == proj_name:
      target_dir = os.path.join(project_dir, subdir)
      project_build_data = _find_dir_build_type(target_dir)
    if project_build_data:
      return project_build_data

  # Recursively look for subdirectory that contains build property file
  for root, _, _ in os.walk(project_dir):
    project_build_data = _find_dir_build_type(root)
    if project_build_data:
      return project_build_data

  return '', ''
