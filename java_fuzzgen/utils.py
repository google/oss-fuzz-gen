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
"""Provides a set of utils for oss-fuzz-gen on Java projects"""

import os
import shutil
import subprocess

from experiment import oss_fuzz_checkout
from java_fuzzgen import oss_fuzz_templates


# Project preparation utils
###########################
def git_clone_project(github_url: str, destination: str) -> bool:
  """Clone project from github url to destination"""
  cmd = ["git clone", github_url, destination]
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


def get_project_name(github_url: str) -> str:
  """Get project name by simplify github url"""
  # Simplify url by cutting https out, then assume what we have left is:
  # HTTP Type
  # github.com/{user}/{proj_name} or github.com/{user}/{proj_name}.git
  # or
  # SSH Type
  # git@github.com:{user}/{proj_name} or git@github.com:{user}/{proj_name}.git
  github_url = github_url.replace(".git", "")
  if github_url.startswith("https://"):
    return github_url.replace("https://", "").split("/")[2]

  if github_url.startswith("http://"):
    return github_url.replace("http://", "").split("/")[2]

  return github_url.split("/")[1]


def get_docker_file(github_repo: str, is_test: bool) -> str:
  """Retrieve Dockerfile content for this project."""
  if is_test:
    return oss_fuzz_templates.DOCKERFILE_JAVA_TEST

  return oss_fuzz_templates.DOCKERFILE_JAVA.replace("TARGET_REPO", github_repo)


def get_build_file(project_dir: str, project_name: str, is_introspector: bool,
                   is_test: bool) -> str:
  """Retrieve build.sh content for this project."""
  if is_test:
    return oss_fuzz_templates.BUILD_JAVA_TEST

  build_type = find_project_build_type(os.path.join(project_dir, "proj"),
                                       project_name)

  if build_type == "ant":
    build_file = oss_fuzz_templates.BUILD_JAVA_ANT
  elif build_type == "gradle":
    build_file = oss_fuzz_templates.BUILD_JAVA_GRADLE
  elif build_type == "maven":
    build_file = oss_fuzz_templates.BUILD_JAVA_MAVEN
  else:
    return ""

  build_file = build_file + oss_fuzz_templates.BUILD_JAVA_BASE

  if is_introspector:
    return build_file + oss_fuzz_templates.BUILD_JAVA_INTROSPECTOR

  return build_file


# Java Project discovery utils
##############################
def _find_dir_build_type(project_dir: str) -> str:
  """Determine the java build project type of the directory"""

  if os.path.exists(os.path.join(project_dir, "pom.xml")):
    return "maven"

  if os.path.exists(os.path.join(
      project_dir, "build.gradle")) or os.path.exists(
          os.path.join(project_dir, "build.gradle.kts")):
    return "gradle"

  if os.path.exists(os.path.join(project_dir, "build.xml")):
    return "ant"

  return ""


def find_project_build_type(project_dir: str, proj_name: str) -> str:
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

  return ""


def is_class_in_project(project_dir: str, class_name: str) -> bool:
  """Find if the given class name is in the project"""
  command = 'grep -ir "class %s\\|interface %s" --include "*.java" %s/proj' % (
      class_name, class_name, project_dir)
  try:
    subprocess.check_output(command, shell=True)
  except subprocess.CalledProcessError:
    return False
  return True


# OSS-Fuzz project utils
########################
def run_oss_fuzz_build(project_dir: str) -> bool:
  """Build the project with OSS-Fuzz commands"""
  cmd = "python3 infra/helper.py build_fuzzers %s" % (project_dir)
  try:
    subprocess.check_call(cmd,
                          shell=True,
                          cwd=oss_fuzz_checkout.OSS_FUZZ_DIR,
                          stdout=subprocess.DEVNULL,
                          stderr=subprocess.DEVNULL)
  except subprocess.CalledProcessError:
    return False
  return True


def refine_project_dir_for_test(autogen_project: str):
  """Refine the oss-fuzz project directory for testing."""
  proj_path = os.path.join(oss_fuzz_checkout.OSS_FUZZ_DIR, "projects",
                           autogen_project)
  built_jar_path = os.path.join(oss_fuzz_checkout.OSS_FUZZ_DIR, "build", "out",
                                autogen_project, "built_jar")

  # Copy built jar to avoid building the project for each testing
  if not os.path.isdir(os.path.join(proj_path, "built_jar")):
    shutil.copytree(built_jar_path, os.path.join(proj_path, "built_jar"))

  # Prepare build.sh for testing
  with open(os.path.join(proj_path, 'build.sh'), 'w') as f:
    f.write(get_build_file("", "", False, True))

  # Prepare Dockerfile for testing
  with open(os.path.join(proj_path, 'Dockerfile'), 'w') as f:
    f.write(get_docker_file("", True))


def test_fuzzer_build(autogen_project: str, harness_source: str) -> bool:
  """Test if fuzzer generated by openai can be built."""
  proj_path = os.path.join(oss_fuzz_checkout.OSS_FUZZ_DIR, "projects",
                           autogen_project)

  # Prepare Fuzzer for testing
  with open(os.path.join(proj_path, 'FuzzTest.java'), 'w') as f:
    f.write(harness_source.replace("class Fuzz", "class FuzzTest"))

  # Test the generated fuzzer
  result = run_oss_fuzz_build(autogen_project)

  # Remove the testing fuzzer
  os.remove(os.path.join(proj_path, 'FuzzTest.java'))

  return result


# OPENAI utils
##############
def get_method_prompt(github_repo: str, func_name: str) -> str:
  """Retrieve and return prompt question for basic methods"""
  with open(
      os.path.join(os.path.dirname(os.path.realpath(__file__)), "prompts",
                   "prompt_methods"), "r") as file:
    return _get_base_prompt(github_repo) % (file.read() % (func_name))

  return ""


def get_constructor_prompt(github_repo: str, class_name: str) -> str:
  """Retrieve and return prompt question for constructors"""
  with open(
      os.path.join(os.path.dirname(os.path.realpath(__file__)), "prompts",
                   "prompt_constructors"), "r") as file:
    return _get_base_prompt(github_repo) % (file.read() % (class_name))

  return ""

def _get_base_prompt(github_repo: str) -> str:
  """Retrieve abd return the base prompt template"""
  with open(
      os.path.join(os.path.dirname(os.path.realpath(__file__)), "prompts",
                   "prompt_base"), "r") as file:
    return file.read() % (get_project_name(github_repo), github_repo, "%s")

  return ""
