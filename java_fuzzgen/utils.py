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

import os
import subprocess

from experiment import oss_fuzz_checkout

# Project preparation utils
###########################
def git_clone_project(github_url, destination):
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


def get_project_name(github_url):
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
  elif github_url.startswith("http://"):
    return github_url.replace("http://", "").split("/")[2]
  else:
    return github_url.split("/")[1]


# Java Project discovery utils
##############################
def _find_dir_build_type(dir):
  """Determine the java build project type of the directory"""

  if os.path.exists(os.path.join(dir, "pom.xml")):
    return "maven"
  elif os.path.exists(os.path.join(dir, "build.gradle")) or os.path.exists(os.path.join(dir, "build.gradle.kts")):
    return "gradle"
  elif os.path.exists(os.path.join(dir, "build.xml")):
    return "ant"
  else:
    return None


def find_project_build_type(dir, proj_name):
    """Search for base project directory to detect project build type"""
    # Search for current directory first
    project_build_type = _find_dir_build_type(dir)
    if project_build_type:
        return project_build_type

    # Search for sub directory with name same as project name
    for subdir in os.listdir(dir):
        if os.path.isdir(os.path.join(dir, subdir)) and subdir == proj_name:
            project_build_type = _find_dir_build_type(os.path.join(
                dir, subdir))
            if project_build_type:
                return project_build_type

    # Recursively look for subdirectory that contains build property file
    for root, _, files in os.walk(dir):
        project_build_type = _find_dir_build_type(root)
        if project_build_type:
            return project_build_type

    return None, None

# OSS-Fuzz project utils
########################
def run_oss_fuzz_build(project_dir):
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


# OPENAI utils
##############
def get_openai_question(github_repo):
  """Retrieve and return openai question from template"""
  with open(os.path.join(os.path.dirname(os.path.realpath(__file__)), "openai_question"), "r") as file:
    return file.read() % (get_project_name(github_repo), github_repo)

  return None
