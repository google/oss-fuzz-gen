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
"""Auto-generate OSS-Fuzz project for a Python GitHub repository."""

import os
import sys
import json
import yaml
import openai
import argparse
import subprocess as sp

from experiment import oss_fuzz_checkout, builder_runner, evaluator
from python_fuzzgen import oss_fuzz_templates

from typing import Any, List


def prepare_oss_fuzz_pre_analysis_project(github_project: str,
                                          autogen_project: str):
  """Create OSS-Fuzz project with build.sh template for running Introspector statically."""
  base_python_project = oss_fuzz_templates.DOCKERFILE_PYTHON_INTROSPECTOR.replace(
      "TARGET_REPO", github_project)

  build_python_project = oss_fuzz_templates.BUILD_PYTHON_INTROSPECTOR
  project_yaml_project = oss_fuzz_templates.PROJECT_YAML_PYTHON_INTROSPETOR.replace(
      "TARGET_REPO", github_project)
  fuzz_project = oss_fuzz_templates.FUZZ_TEMPLATE_PYTHON

  # Find the next auto-fuzz dir
  project_dir = os.path.join(oss_fuzz_checkout.OSS_FUZZ_DIR, "projects",
                             autogen_project)
  print("Creating project: %s" % (project_dir))
  if not os.path.isdir(project_dir):
    os.mkdir(project_dir)

  # Write template files
  with open(os.path.join(project_dir, 'Dockerfile'), 'w') as f:
    f.write(base_python_project)

  with open(os.path.join(project_dir, 'build.sh'), 'w') as f:
    f.write(build_python_project)

  with open(os.path.join(project_dir, 'project.yaml'), 'w') as f:
    f.write(project_yaml_project)

  with open(os.path.join(project_dir, 'fuzz_1.py'), 'w') as f:
    f.write(fuzz_project)

  return autogen_project


def get_next_autofuzz_dir():
  print("OSS-Fuzz dir: %s" % (oss_fuzz_checkout.OSS_FUZZ_DIR))
  auto_gen = 'autofuzz-dir-'
  max_idx = -1
  for l in os.listdir(os.path.join(oss_fuzz_checkout.OSS_FUZZ_DIR, "projects")):
    if l.startswith(auto_gen):
      tmp_dir_idx = int(l.replace(auto_gen, ""))
      if tmp_dir_idx > max_idx:
        max_idx = tmp_dir_idx
  return '%s%d' % (auto_gen, max_idx + 1)


def run_oss_fuzz_build(project_dir):
  cmd = "python3 infra/helper.py build_fuzzers %s" % (project_dir)
  try:
    sp.check_call(cmd,
                  shell=True,
                  cwd=oss_fuzz_checkout.OSS_FUZZ_DIR,
                  stdout=sp.DEVNULL,
                  stderr=sp.DEVNULL)
  except sp.CalledProcessError:
    return False
  return True


def load_introspector_functions_output(autogen_project):
  """For a given OSS-Fuzz project, read the Fuzz Introspector output."""
  # Target dir
  introspector_output = os.path.join(oss_fuzz_checkout.OSS_FUZZ_DIR, 'build',
                                     'out', autogen_project,
                                     'fuzzerLogFile-fuzz_1.data.yaml')

  with open(introspector_output, 'r') as f:
    introspector_analysis = yaml.safe_load(f)

  all_introspector_funcs = introspector_analysis['All functions']['Elements']

  return all_introspector_funcs


def create_sample_harness(github_repo: str, func_elem):

  prompt_template = """Hi, I'm looking for your help to write a Python fuzzing harness for the %s Python project. The project is located at %s and I would like you to write a harness targeting this module. You should use the Python Atheris framework for writing the fuzzer. Could you please show me the source code for this harness?

            The specific function you should target is %s and please wrap all code in <code> tags.

			I only want the actual harness function that passes the fuzzer's data into the target function and not a whole Python module. This function should be called "fuzz_%s" and you should only show this code. Please do not show any other code.

            The harness should handle any exceptions and must include the code:
```
  atheris.instrument_all()
  atheris.Setup(sys.argv, TestOneInput)
  atheris.Fuzz()
```
            There should be no call at all to `with atheris.instrumented_function()` and the harness function should not involve calls to functions the atheris module.

            Finally, could you make sure that the following is used to seed the fuzz data? `atheris.FuzzedDataProvider(data)` and `fdp.ConsumeUnicodeNoSurrogates(1024)`.

			The function signature for the target is %s and please wrap all code in <code> tags.""" % (
      github_repo.split("/")[-1], github_repo, func_elem['functionName'],
      github_repo.split("/")[-1].replace("-", "_"), func_elem['functionName'])
  completion = openai.ChatCompletion.create(model="gpt-3.5-turbo",
                                            messages=[
                                                {
                                                    "role": "system",
                                                    "content": prompt_template
                                                },
                                            ])
  fuzzer_source = completion.choices[0].message.content.replace(
      "<code>", "").replace("</code>", "").replace("```python",
                                                   "").replace("```", "")

  #print(">"*45)
  #print(fuzzer_source)
  #print(">"*45)
  return fuzzer_source


def build_and_evalute_fuzzer_harnesses(fuzzer_sources, autogen_project,
                                       log_file, github_project):
  """Builds a Python project, runs each of the fuzzers built and logs stats."""
  idx = 0
  for idx in range(len(fuzzer_sources)):
    print("------")
    print(oss_fuzz_checkout.OSS_FUZZ_DIR)
    fuzzer_path = os.path.join(oss_fuzz_checkout.OSS_FUZZ_DIR, "projects",
                               autogen_project, "fuzz_%d.py" % (idx))
    with open(fuzzer_path, "w") as f:
      f.write(fuzzer_sources[idx])

  # Refined build
  with open(
      os.path.join(oss_fuzz_checkout.OSS_FUZZ_DIR, "projects", autogen_project,
                   "build.sh"), "w") as f:
    f.write(oss_fuzz_templates.BUILD_PYTHON_HARNESSES)

  # Build fuzzers
  python_runner = builder_runner.BuilderRunner("fuzz_1", "ww", 60)
  python_runner.build_and_run_python(autogen_project, "fuzz_%d" % (idx))

  # Run each of the fuzzers
  stat_list = list()
  for idx in range(len(fuzzer_sources)):
    print("------")
    print(oss_fuzz_checkout.OSS_FUZZ_DIR)
    print("Running")

    fuzz_logs = "/tmp/fuzz-%d-log.txt" % (idx)
    python_runner.run_target_local_python(autogen_project, "fuzz_%d" % (idx),
                                          fuzz_logs)

    valuator = evaluator.Evaluator(None, None, None)

    with open(fuzz_logs, 'rb') as f:
      cov_pcs, total_pcs, crashes, is_driver_fuzz_err, driver_fuzz_err = valuator._parse_libfuzzer_logs(
          f, None)

    stats = {
        'cov_pcs': cov_pcs,
        'total_pcs': total_pcs,
        'crashes': crashes,
        'is_driver_fuzz_err': is_driver_fuzz_err,
        'driver_fuzz_err': driver_fuzz_err
    }

    result_status = {
        'stats': stats,
        'idx': idx,
        'fuzzer-source': fuzzer_sources[idx]
    }
    stat_list.append(result_status)

    #print("cov_pcs: {%d} -- total_pcs: {%d}"%(cov_pcs, total_pcs))
    #builder_runner.build_and_run(autogen_project, "fuzz_%d"%(idx), 0)

  if log_file:
    with open(log_file, "w") as f:
      f.write("Target: %s\n" % (github_project))
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

  print("Total stats:")
  for stat in sorted(stat_list, key=lambda x: x['stats']['cov_pcs']):
    print("idx: %d -- cov_pcs: %d" % (stat['idx'], stat['stats']['cov_pcs']))


def perform_pre_analysis(github_project, autogen_project):
  """Creates an OSS-Fuzz project for a project and runs introspector
    statically on it within the OSS-Fuzz environment."""
  autogen_project = prepare_oss_fuzz_pre_analysis_project(
      github_project, autogen_project)

  # Run the build
  if not run_oss_fuzz_build(autogen_project):
    return None

  # Extract the harnesses logic
  all_introspector_funcs = load_introspector_functions_output(autogen_project)

  return all_introspector_funcs


def generate_python_fuzzers(github_project: str, introspector_funcs: List[Any],
                            max_targets: int) -> List[str]:
  """Runs Python fuzzer harness generation on a list of function from fuzz introspector."""
  idx = 0
  fuzzer_sources = []
  for func in introspector_funcs:
    idx += 1
    if idx >= max_targets:
      break
    harness_source = create_sample_harness(github_project, func)
    fuzzer_sources.append(harness_source)
  return fuzzer_sources


def auto_fuzz_from_scratch(github_repo: str, log_file: str, max_targets: int):
  """Auto-generates an OSS-Fuzz project with |max_targets| fuzzers and evalutes the fuzzers."""
  oss_fuzz_checkout.clone_oss_fuzz(delete_at_exit = False)

  autogen_project = get_next_autofuzz_dir()

  introspector_funcs = perform_pre_analysis(github_repo, autogen_project)
  if not introspector_funcs:
    return False

  fuzzer_sources = generate_python_fuzzers(github_repo, introspector_funcs,
                                           max_targets)
  if len(fuzzer_sources) == 0:
    print("Could not generate any fuzzers")
    return

  # Build all the fuzzers and evaluate each of them
  build_and_evalute_fuzzer_harnesses(fuzzer_sources, autogen_project, log_file,
                                     github_repo)

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
