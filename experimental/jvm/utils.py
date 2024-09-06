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
from urllib3.util import parse_url

import oss_fuzz_templates

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
  build_file = _get_build_file(base_dir, project_name)
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


def _get_build_file(base_dir: str, project_name: str) -> str:
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

  return build_file + oss_fuzz_templates.BUILD_JAVA_BASE


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
