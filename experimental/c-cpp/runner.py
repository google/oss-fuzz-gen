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
"""Manager for running auto-gen from scratch."""

import argparse
import os
import shutil
import subprocess
import threading
from typing import List

silent_global = False

empty_oss_fuzz_build = """#!/bin/bash -eu
# Copyright 2018 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################
"""

empty_oss_fuzz_docker = """# Copyright 2018 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################

FROM gcr.io/oss-fuzz-base/base-builder
RUN apt-get update && apt-get install -y make autoconf automake libtool cmake \
                      pkg-config curl check
RUN rm /usr/local/bin/cargo && \
 curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | bash -s -- -y && \
 apt-get install -y cargo
RUN python3 -m pip install --upgrade pip && \
    python3 -m pip install pydantic-core pyyaml cxxfilt openai==1.16.2
COPY *.py $SRC/
WORKDIR $SRC
COPY build.sh $SRC/"""

empty_project_yaml = """homepage: "https://github.com/google/oss-fuzz"
language: c++
primary_contact: "info@oss-fuzz.com"
auto_ccs:
-
main_repo: 'https://github.com/samtools/htslib.git'
"""


def setup_worker_project(oss_fuzz_base: str, project_name: str):
  """Setup empty OSS-Fuzz project used for analysis."""
  temp_project_dir = os.path.join(oss_fuzz_base, "projects", project_name)
  if os.path.isdir(temp_project_dir):
    shutil.rmtree(temp_project_dir)

  os.makedirs(temp_project_dir)
  with open(os.path.join(temp_project_dir, "project.yaml"), 'w') as f:
    f.write(empty_project_yaml)
  with open(os.path.join(temp_project_dir, "build.sh"), 'w') as f:
    f.write(empty_oss_fuzz_build)
  with open(os.path.join(temp_project_dir, "Dockerfile"), 'w') as f:
    f.write(empty_oss_fuzz_docker)

  # Copy over the generator
  files_to_copy = {'build_generator.py', 'manager.py'}
  for target_file in files_to_copy:
    shutil.copyfile(
        os.path.join(os.path.dirname(os.path.abspath(__file__)), target_file),
        os.path.join(temp_project_dir, target_file))

  # Build a version of the project
  if silent_global:
    subprocess.check_call("python3 infra/helper.py build_fuzzers %s" %
                          (project_name),
                          shell=True,
                          cwd=oss_fuzz_base,
                          stdout=subprocess.DEVNULL,
                          stderr=subprocess.DEVNULL)
  else:
    subprocess.check_call("python3 infra/helper.py build_fuzzers %s" %
                          (project_name),
                          shell=True,
                          cwd=oss_fuzz_base)


def run_autogen(github_url,
                outdir,
                openai_api_key,
                oss_fuzz_base,
                worker_project,
                disable_autofuzz,
                targets_per_heuristic=5):
  """Launch auto-gen analysis within OSS-Fuzz container."""

  initiator_cmd = 'python3 /src/manager.py %s -o %s' % (github_url, outdir)
  if disable_autofuzz:
    initiator_cmd += ' --disable-fuzzgen'
  initiator_cmd += ' --targets-per-heuristic=%d' % (targets_per_heuristic)

  cmd = [
      "docker",
      "run",
      "-e",
      'FUZZING_ENGINE=libfuzzer',
      '-e',
      'SANITIZER=address',
      '-e',
      'ARCHITECTURE=x86_64',
      '-e',
      'HELPER=True',
      '-e',
      'FUZZING_LANGUAGE=c++',
      '-e',
      'OPENAI_API_KEY=%s' % (openai_api_key),
      '-v',
      '%s/build/out/%s:/out' % (oss_fuzz_base, worker_project),
      '-v',
      '%s/build/work/%s:/work' % (oss_fuzz_base, worker_project),
      '-t',
      'gcr.io/oss-fuzz/%s' % (worker_project),
      # Command to run inside the container
      initiator_cmd
  ]

  cmd_to_run = ' '.join(cmd)
  try:
    if silent_global:
      subprocess.check_call(cmd_to_run,
                            cwd=oss_fuzz_base,
                            shell=True,
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.STDOUT)
    else:
      subprocess.check_call(cmd_to_run, cwd=oss_fuzz_base, shell=True)
  except subprocess.CalledProcessError:
    pass


def read_targets_file(filename: str) -> List[str]:
  """Parse input file."""
  res_targets = []
  with open(filename, 'r') as f:
    targets = f.read().split("\n")
    for e in targets:
      if len(e) < 6:
        continue
      if e:
        res_targets.append(e)
  return res_targets


def run_on_targets(target,
                   oss_fuzz_base,
                   worker_project_name,
                   idx,
                   semaphore=None,
                   disable_autofuzz=False,
                   targets_per_heuristic=5):
  """Thread entry point for single project auto-gen."""

  if semaphore is not None:
    semaphore.acquire()

  openai_api_key = os.getenv("OPENAI_API_KEY")

  outdir = '/out/autogen-results-%d' % (idx)
  with open('status-log.txt', 'a') as f:
    f.write("Targeting: %s :: %d\n" % (target, idx))
  run_autogen(target, outdir, openai_api_key, oss_fuzz_base,
              worker_project_name, disable_autofuzz, targets_per_heuristic)

  if semaphore is not None:
    semaphore.release()


def get_next_worker_project(oss_fuzz_base: str) -> str:
  """Gets next OSS-Fuzz worker projecet."""
  max_idx = -1
  for project_dir in os.listdir(os.path.join(oss_fuzz_base, 'projects')):
    if not 'temp-project-' in project_dir:
      continue
    try:
      tmp_idx = int(project_dir.replace('temp-project-', ''))
      max_idx = max(tmp_idx, max_idx)
    except:
      continue
  return f'temp-project-{max_idx+1}'


def run_parallels(oss_fuzz_base, target_repositories, disable_autofuzz,
                  targets_per_heuristic):
  """Run auto-gen on a list of projects in parallel.

  Parallelisation is done by way of threads. Practically
  all of the computation will happen inside an OSS-Fuzz
  Docker container and not within this Python script as such."""
  semaphore_count = 6
  semaphore = threading.Semaphore(semaphore_count)
  jobs = []
  for idx, target in enumerate(target_repositories):
    worker_project_name = get_next_worker_project(oss_fuzz_base)
    print(f'Worker project name {worker_project_name}')

    setup_worker_project(oss_fuzz_base, worker_project_name)
    proc = threading.Thread(target=run_on_targets,
                            args=(target, oss_fuzz_base, worker_project_name,
                                  idx, semaphore, disable_autofuzz,
                                  targets_per_heuristic))
    jobs.append(proc)
    proc.start()

  for proc in jobs:
    proc.join()


def run_sequential(oss_fuzz_base, target_repositories, disable_autofuzz,
                   targets_per_heuristic):
  """Run auto-gen on a list of projects sequentially."""
  for idx, target in enumerate(target_repositories):
    worker_project_name = get_next_worker_project(oss_fuzz_base)
    run_on_targets(target, oss_fuzz_base, worker_project_name, idx,
                   disable_autofuzz, targets_per_heuristic)


def parse_commandline():
  """Parse the commandline."""
  parser = argparse.ArgumentParser()
  parser.add_argument('--oss-fuzz', '-o', help='OSS-Fuzz base')
  parser.add_argument('--input', '-i', help='Input to analyze')
  parser.add_argument('--disable-fuzzgen',
                      action='store_true',
                      help='Disable fuzz generation')
  parser.add_argument("--targets-per-heuristic",
                      "-t",
                      help='Number of harness to generate per heuristic.',
                      type=int,
                      default=15)
  parser.add_argument("--silent",
                      "-s",
                      help='Disable logging in subprocess.',
                      action='store_true')
  return parser.parse_args()


def main():
  global silent_global

  args = parse_commandline()
  oss_fuzz_base = args.oss_fuzz
  target = args.input
  disable_autofuzz = args.disable_fuzzgen

  if os.path.isfile(target):
    target_repositories = read_targets_file(target)
  else:
    target_repositories = [target]
  print(target_repositories)

  silent_global = args.silent

  use_multithreading = True
  if use_multithreading:
    run_parallels(oss_fuzz_base, target_repositories, disable_autofuzz,
                  args.targets_per_heuristic)
  else:
    run_sequential(oss_fuzz_base, target_repositories, disable_autofuzz,
                   args.targets_per_heuristic)


if __name__ == "__main__":
  main()
