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
"""Auto-generate OSS-Fuzz project for a Java GitHub repository."""

import os
import sys
import json
import yaml
import openai
import argparse
import subprocess as sp

from experiment import oss_fuzz_checkout
from java_fuzzgen import oss_fuzz_templates, utils

from typing import Any, List


def get_next_autofuzz_dir():
  print("OSS-Fuzz dir: %s" % (oss_fuzz_checkout.OSS_FUZZ_DIR))
  auto_gen = 'java-autofuzz-dir-'
  max_idx = -1
  for l in os.listdir(os.path.join(oss_fuzz_checkout.OSS_FUZZ_DIR, "projects")):
    if l.startswith(auto_gen):
      tmp_dir_idx = int(l.replace(auto_gen, ""))
      if tmp_dir_idx > max_idx:
        max_idx = tmp_dir_idx
  return '%s%d' % (auto_gen, max_idx + 1)


def prepare_oss_fuzz_pre_analysis_project(github_repo: str,
                                          autogen_project: str):
  """Create OSS-Fuzz project with build.sh template for running Introspector statically."""
  # Find the next auto-fuzz dir
  project_dir = os.path.join(oss_fuzz_checkout.OSS_FUZZ_DIR, "projects",
                             autogen_project)
  print("Creating project: %s" % (project_dir))
  if not os.path.isdir(project_dir):
    os.mkdir(project_dir)

  # Clone projects
  result = utils.git_clone_project(github_repo, os.path.join(project_dir, "proj"))
  if not result:
    print("Failed to clone project")
    return None

  # Determine java build type
  project_name = utils.get_project_name(github_repo)
  build_type = utils.find_project_build_type(os.path.join(project_dir, "proj"), project_name)

  # Write template files
  if build_type == "ant":
    build_file = oss_fuzz_templates.BUILD_JAVA_ANT
  elif build_type == "gradle":
    build_file = oss_fuzz_templates.BUILD_JAVA_GRADLE
  elif build_type == "maven":
    build_file = oss_fuzz_templates.BUILD_JAVA_MAVEN
  else:
    print("Build type of this java project is not supported.")
    return None

  build_file = build_file + oss_fuzz_templates.BUILD_JAVA_BASE + oss_fuzz_templates.BUILD_JAVA_INTROSPECTOR

  with open(os.path.join(project_dir, 'build.sh'), 'w') as f:
    f.write(build_file)

  with open(os.path.join(project_dir, 'Dockerfile'), 'w') as f:
    f.write(oss_fuzz_templates.DOCKERFILE_JAVA.replace("TARGET_REPO", github_repo))

  with open(os.path.join(project_dir, 'project.yaml'), 'w') as f:
    f.write(oss_fuzz_templates.YAML_JAVA.replace("TARGET_REPO", github_repo))

  with open(os.path.join(project_dir, 'Fuzz.java'), 'w') as f:
    f.write(oss_fuzz_templates.FUZZER_JAVA)

  return autogen_project


def perform_pre_analysis(github_repo, autogen_project):
  """Creates an OSS-Fuzz project for a project and runs introspector
    statically on it within the OSS-Fuzz environment."""
  autogen_project = prepare_oss_fuzz_pre_analysis_project(
      github_repo, autogen_project)

  if not autogen_project:
    return None

  # Run the build
  if not utils.run_oss_fuzz_build(autogen_project):
    return None

  # Extract the harnesses logic
  introspector_output = os.path.join(oss_fuzz_checkout.OSS_FUZZ_DIR, 'build',
                                     'out', autogen_project,
                                     'fuzzerLogFile-Fuzz.data.yaml')

  # Extract fuzz introspector output
  with open(introspector_output, 'r') as f:
    introspector_analysis = yaml.safe_load(f)

  all_introspector_funcs = introspector_analysis['All functions']['Elements']

  return all_introspector_funcs


def create_harness_from_openai(github_repo: str):
  question = utils.get_openai_question(github_repo)

  if not question:
    print("Failed to locate default openai question template.")
    return None

  completion = openai.chat.completions.create(model="gpt-3.5-turbo",
                                            messages=[
                                                {
                                                    "role": "system",
                                                    "content": question
                                                },
                                            ])
  print(completion.choices[0].message.content)

  return completion.choices[0].message.content


def generate_fuzzers(github_repo: str, introspector_funcs: List[Any], max_targets: int) -> List[str]:
  """Runs java fuzzer harness generation on a list of function from fuzz introspector result"""
  idx = 0
  fuzzer_sources = []
  for func in introspector_funcs:
    idx += 1
    if idx >= max_targets:
      break
    harness_source = create_harness_from_openai(github_repo)
    if harness_source:
      fuzzer_sources.append(harness_source)
  return fuzzer_sources


def auto_fuzz_from_scratch(github_repo: str, log_file: str, max_targets: int):
  """Auto-generates an OSS-Fuzz project with |max_targets| fuzzers and evalutes the fuzzers."""
  # Clone and retrieve OSS-Fuzz
  oss_fuzz_checkout.clone_oss_fuzz()

  # Generate new project directory in OSS-Fuzz/projects
  autogen_project = get_next_autofuzz_dir()

  # Peform static analysis by fuzz-introspector
  introspector_funcs = perform_pre_analysis(github_repo, autogen_project)
  if not introspector_funcs:
    return False

  # Generate fuzzers
  fuzzer_sources = generate_fuzzers(github_repo, introspector_funcs, max_targets)
  if len(fuzzer_sources) == 0:
    print("Could not generate any fuzzers")
    return

  # Build all the fuzzers and evaluate each of them
#  build_and_evalute_fuzzer_harnesses(fuzzer_sources, autogen_project, log_file,
#                                     github_repo)

  # Show output
  print("------")
  print("OSS-Fuzz dir used: %s" % (oss_fuzz_checkout.OSS_FUZZ_DIR))
  print("Auto-generated project: %s" % (os.path.join(
      oss_fuzz_checkout.OSS_FUZZ_DIR, "projects", autogen_project)))


def parse_args():
  parser = argparse.ArgumentParser()
  parser.add_argument("-r",
                      "--repo",
                      help="Target repository to fuzz.",
                      default='')
  parser.add_argument("-l", "--log-file", help='Log file.', default=None)
  parser.add_argument("-m",
                      "--max-targets",
                      help='Max number of function targets',
                      default=40,
                      type=int)

  args = parser.parse_args()
  return args


def main():
  args = parse_args()
  auto_fuzz_from_scratch(args.repo, args.log_file, args.max_targets)


if __name__ == "__main__":
  main()
