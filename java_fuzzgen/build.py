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

import argparse
import os
from typing import Any, Dict, List, Tuple

import openai
import yaml

from experiment import (benchmark, builder_runner, evaluator,
                        oss_fuzz_checkout, workdir)
from java_fuzzgen import oss_fuzz_templates, utils
from java_fuzzgen.objects import java_method


def get_next_autofuzz_dir() -> str:
  auto_gen = 'java-autofuzz-dir-'
  max_idx = -1
  for l in os.listdir(os.path.join(oss_fuzz_checkout.OSS_FUZZ_DIR, "projects")):
    if l.startswith(auto_gen):
      tmp_dir_idx = int(l.replace(auto_gen, ""))
      if tmp_dir_idx > max_idx:
        max_idx = tmp_dir_idx
  return '%s%d' % (auto_gen, max_idx + 1)


def prepare_oss_fuzz_pre_analysis_project(github_repo: str,
                                          autogen_project: str) -> str:
  """Create OSS-Fuzz project for running Introspector statically."""
  # Find the next auto-fuzz dir
  project_dir = os.path.join(oss_fuzz_checkout.OSS_FUZZ_DIR, "projects",
                             autogen_project)
  print("Creating project: %s" % (project_dir))
  if not os.path.isdir(project_dir):
    os.mkdir(project_dir)

  # Clone projects
  result = utils.git_clone_project(github_repo,
                                   os.path.join(project_dir, "proj"))
  if not result:
    print("Failed to clone project")
    return ""

  # Determine java build type
  project_name = utils.get_project_name(github_repo)
  build_file = utils.get_build_file(project_dir, project_name, True, False)

  if not build_file:
    print("Build type of this java project is not supported.")
    return ""

  with open(os.path.join(project_dir, 'build.sh'), 'w') as f:
    f.write(build_file)

  with open(os.path.join(project_dir, 'Dockerfile'), 'w') as f:
    f.write(utils.get_docker_file(github_repo, False))

  with open(os.path.join(project_dir, 'project.yaml'), 'w') as f:
    f.write(oss_fuzz_templates.YAML_JAVA.replace("TARGET_REPO", github_repo))

  with open(os.path.join(project_dir, 'Fuzz.java'), 'w') as f:
    f.write(oss_fuzz_templates.FUZZER_JAVA)

  return autogen_project


def perform_pre_analysis(github_repo, autogen_project) -> Tuple[Any, List[Any]]:
  """Creates an OSS-Fuzz project for a project and runs introspector
    statically on it within the OSS-Fuzz environment."""
  print("Performing static analysis with fuzz-introspector...")

  autogen_project = prepare_oss_fuzz_pre_analysis_project(
      github_repo, autogen_project)

  if not autogen_project or not utils.run_oss_fuzz_build(autogen_project):
    print("Failed to build project with JDK15.")
    return None, []

  # Extract the harnesses logic
  introspector_output = os.path.join(oss_fuzz_checkout.OSS_FUZZ_DIR, 'build',
                                     'out', autogen_project,
                                     'fuzzerLogFile-Fuzz.data.yaml')
  bench = benchmark.Benchmark.from_yaml(introspector_output)

  # Extract fuzz introspector output
  with open(introspector_output, 'r') as f:
    introspector_analysis = yaml.safe_load(f)

  all_introspector_funcs = introspector_analysis['All functions']['Elements']

  return bench, all_introspector_funcs


def create_harness_from_openai(github_repo: str, func_elem: Dict,
                               proj_path: str) -> str:
  """Create fuzzing harness with openai prompts"""
  # Generate objects for this speific function element dict
  java_method_object = java_method.JAVAMETHOD(func_elem)

  # Skip non-project method and uninterested method
  if not utils.is_class_in_project(proj_path,
                                   java_method_object.full_qualified_class_name
                                  ) or java_method_object.is_skip():
    return ""

  # Generate the prompt for this specific method or constructor
  if java_method_object.is_constructor:
    prompt = utils.get_constructor_prompt(github_repo,
                                          java_method_object.class_name)
  else:
    prompt = utils.get_method_prompt(github_repo,
                                     java_method_object.full_qualified_name)

  if not prompt:
    print("Failed to locate default prompt template.")
    return ""

  # Querying openai for a sample fuzzing harness
  completion = openai.chat.completions.create(model="gpt-3.5-turbo",
                                              messages=[
                                                  {
                                                      "role": "system",
                                                      "content": prompt
                                                  },
                                              ])

  # Extract fuzzer code and remove unwanted tags
  if completion.choices[0].message.content:
    source_code = completion.choices[0].message.content.split(
        "<java_code>")[-1].split("</java_code>")[0]
    source_code = source_code.split("```java")[-1].split("```")[0]
    source_code = source_code.replace(
        "public class", "//Target method: %s\npublic class" %
        (java_method_object.full_qualified_name))
    return source_code

  return ""


def generate_fuzzers(github_repo: str, introspector_funcs: List[Any],
                     max_targets: int, autogen_project: str) -> List[str]:
  """Generate java fuzzers on a list of methods from fuzz introspector result"""
  print("Generating fuzzers...")
  idx = 0
  fuzzer_sources = []
  proj_path = os.path.join(oss_fuzz_checkout.OSS_FUZZ_DIR, "projects",
                           autogen_project)
  for func in introspector_funcs:
    if idx >= max_targets:
      break
    harness_source = create_harness_from_openai(github_repo, func, proj_path)

    if harness_source:
      if utils.test_fuzzer_build(autogen_project, harness_source):
        idx += 1
        fuzzer_sources.append(harness_source)

  return fuzzer_sources


def build_and_evalute_fuzzer_harnesses(
    fuzzer_sources: List[str], autogen_project: str, log_file: str,
    github_repo: str, bench: benchmark.Benchmark) -> Tuple[bool, int, int, int]:
  """Builds a Java project, runs each of the fuzzers built and logs stats."""
  idx = 0
  print("Building and evaluating fuzzers...")

  # Retrieve fuzzers
  for idx, fuzzer_source in enumerate(fuzzer_sources):
    fuzzer_name = "Fuzz%d" % (idx)
    fuzzer_path = os.path.join(oss_fuzz_checkout.OSS_FUZZ_DIR, "projects",
                               autogen_project, "%s.java" % (fuzzer_name))
    with open(fuzzer_path, "w") as f:
      f.write(fuzzer_source.replace("class Fuzz", "class %s" % (fuzzer_name)))

  # Build fuzzers
  work_dir = workdir.WorkDirs("ww")
  fuzzer_runner = builder_runner.BuilderRunner(bench, work_dir, 60)
  if not utils.run_oss_fuzz_build(autogen_project):
    return False, 0, 0, 0

  # Run each fuzzers
  stat_list = []
  for idx, fuzzer_source in enumerate(fuzzer_sources):
    fuzz_logs = "/tmp/%s-%d-log.txt" % (autogen_project, idx)
    # Java project requires longer to stop the JVM and end.
    fuzzer_runner.run_target_local(autogen_project,
                                   "Fuzz%d" % (idx),
                                   fuzz_logs,
                                   is_benchmark=False,
                                   end_wait=60)

    valuator = evaluator.Evaluator(fuzzer_runner, bench, work_dir)

    proj_path = os.path.join(oss_fuzz_checkout.OSS_FUZZ_DIR, "projects",
                             autogen_project)
    with open(fuzz_logs, 'rb') as f:
      cov_pcs, total_pcs, crashes, is_err = valuator.parse_libfuzzer_logs(
          f, evaluator.Logger(proj_path))

    stats = {
        'cov_pcs': cov_pcs,
        'total_pcs': total_pcs,
        'crashes': crashes,
        'is_driver_fuzz_err': is_err
    }

    result_status = {'stats': stats, 'idx': idx, 'fuzzer-source': fuzzer_source}
    stat_list.append(result_status)

  if log_file:
    with open(log_file, "a") as f:
      f.write("############################")
      f.write("Target: %s\n" % (github_repo))
      f.write("# High level stats\n")
      for stat in sorted(stat_list, key=lambda x: x['stats']['cov_pcs']):
        f.write("idx: %d -- cov_pcs: %d\n" %
                (stat['idx'], stat['stats']['cov_pcs']))
      f.write("\n")
      f.write("-" * 45 + "\n")
      f.write("# Fuzzer sources\n")
      for stat in sorted(stat_list, key=lambda x: x['stats']['cov_pcs']):
        f.write("idx: %d -- cov_pcs: %d\n" %
                (stat['idx'], stat['stats']['cov_pcs']))
        f.write("-" * 45 + "\n")
        f.write(stat['fuzzer-source'])
        f.write("\n")
        f.write("-" * 45 + "\n")
      f.write("############################")

  print("Total stats:")
  sorted_fuzzers = sorted(stat_list, key=lambda x: x['stats']['cov_pcs'])
  for stat in sorted_fuzzers:
    print("idx: %d -- cov_pcs: %d" % (stat['idx'], stat['stats']['cov_pcs']))

  min_cov = sorted_fuzzers[0]['stats']['cov_pcs']
  max_cov = sorted_fuzzers[-1]['stats']['cov_pcs']
  fuzzer_count = len(sorted_fuzzers)

  return True, min_cov, max_cov, fuzzer_count


def auto_fuzz_from_scratch(github_repo: str, log_file: str,
                           max_targets: int) -> str:
  """Auto-generates an OSS-Fuzz project and evalutes the fuzzers."""
  # Generate new project directory in OSS-Fuzz/projects
  autogen_project = get_next_autofuzz_dir()

  # Peform static analysis by fuzz-introspector
  bench, introspector_funcs = perform_pre_analysis(github_repo, autogen_project)
  if len(introspector_funcs) == 0:
    return "%s,No,,,\n" % (github_repo)

  # Generate fuzzers
  utils.refine_project_dir_for_test(autogen_project)
  fuzzer_sources = generate_fuzzers(github_repo, introspector_funcs,
                                    max_targets, autogen_project)
  if len(fuzzer_sources) == 0:
    print("Could not generate any fuzzers")
    return "%s,Yes,0,,\n" % (github_repo)

  # Refined build file and Dockerfile
  project_dir = os.path.join(oss_fuzz_checkout.OSS_FUZZ_DIR, "projects",
                             autogen_project)
  project_name = utils.get_project_name(github_repo)
  with open(
      os.path.join(oss_fuzz_checkout.OSS_FUZZ_DIR, "projects", autogen_project,
                   "build.sh"), "w") as f:
    f.write(utils.get_build_file(project_dir, project_name, False, False))
  with open(
      os.path.join(oss_fuzz_checkout.OSS_FUZZ_DIR, "projects", autogen_project,
                   "Dockerfile"), "w") as f:
    f.write(utils.get_docker_file(github_repo, False))

  # Build all the fuzzers and evaluate each of them
  result, min_cov, max_cov, fuzzer_count = build_and_evalute_fuzzer_harnesses(
      fuzzer_sources, autogen_project, log_file, github_repo, bench)

  # Show output
  print("------")
  print("OSS-Fuzz dir used: %s" % (oss_fuzz_checkout.OSS_FUZZ_DIR))
  print("Auto-generated project: %s" % (os.path.join(
      oss_fuzz_checkout.OSS_FUZZ_DIR, "projects", autogen_project)))

  if result:
    return "%s,Yes,%d,%d,%d\n" % (github_repo, fuzzer_count, max_cov, min_cov)

  return "%s,Yes,0,,\n" % (github_repo)


def parse_args():
  """Parse command line arguments"""
  parser = argparse.ArgumentParser()
  parser.add_argument(
      "-r",
      "--repo",
      help="Target repositories to fuzz, separated by comma(,).",
      default=None)
  parser.add_argument(
      "-rf",
      "--repo-file",
      help=
      "Target repositories to fuzz in a file, separated by new line character.",
      default=None)
  parser.add_argument("-l", "--log-file", help='Log file.', default=None)
  parser.add_argument("-s",
                      "--summary-file",
                      help='Summary file.',
                      default=None)
  parser.add_argument("-m",
                      "--max-targets",
                      help='Max number of function targets',
                      default=40,
                      type=int)

  args = parser.parse_args()
  return args


def main():
  args = parse_args()

  if args.repo:
    repos = args.repo.split(",")
  elif args.repo_file:
    with open(args.repo_file, "r") as file:
      repos = file.read().split("\n")
  else:
    print("No repository specified.")
    return

  oss_fuzz_checkout.clone_oss_fuzz()
  print("OSS-Fuzz dir: %s" % (oss_fuzz_checkout.OSS_FUZZ_DIR))

  if args.summary_file:
    with open(args.summary_file, "w") as f:
      f.write(
          r"""Project,Build Success?,\# success fuzzers, Max Cov,Min Cov\\n""")

  for repo in repos:
    if not repo:
      continue
    print("####################################################")
    print("Processing %s" % (repo))
    result = auto_fuzz_from_scratch(repo, args.log_file, args.max_targets)
    if args.summary_file:
      with open(args.summary_file, "a") as f:
        f.write(result)
    print("####################################################")


if __name__ == "__main__":
  main()
