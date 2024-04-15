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
import sys
import shutil
import multiprocessing
import subprocess

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
################################################################################"""

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
RUN apt-get update && apt-get install -y make autoconf automake cmake
RUN python3 -m pip install pyyaml cxxfilt openai==0.27.8
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
  shutil.copyfile(
      os.path.join(os.path.dirname(os.path.abspath(__file__)),
                   "build-generator.py"),
      os.path.join(temp_project_dir, "build-generator.py"))

  # Build a version of the project
  subprocess.check_call("python3 infra/helper.py build_fuzzers %s" %
                        (project_name),
                        shell=True,
                        cwd=oss_fuzz_base)


def run_autogen(github_url, outdir, openai_api_key, oss_fuzz_base,
                worker_project):
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
      'python3 /src/build-generator.py %s -o %s' % (github_url, outdir)
  ]

  cmd_to_run = ' '.join(cmd)
  try:
    subprocess.check_call(cmd_to_run, cwd=oss_fuzz_base, shell=True)
  except subprocess.CalledProcessError:
    pass


def read_targets_file(filename):
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
                   semaphore=None):
  if semaphore is not None:
    semaphore.acquire()

  setup_worker_project(oss_fuzz_base, worker_project_name)
  openai_api_key = os.getenv("OPENAI_API_KEY")

  outdir = '/out/autogen-results-%d' % (idx)
  with open('status-log.txt', 'a') as f:
    f.write("Targeting: %s :: %d\n" % (target, idx))
  run_autogen(target, outdir, openai_api_key, oss_fuzz_base,
              worker_project_name)

  if semaphore is not None:
    semaphore.release()


def run_parallels(oss_fuzz_base, target_repositories):
  """Run auto-gen on a list of projects in parallel.

  Parallelisation is done by way of multiprocess. Practically
  all of the computation will happen inside an OSS-Fuzz
  Docker container and not within this Python script as such."""
  semaphore_count = 4
  semaphore = multiprocessing.Semaphore(semaphore_count)
  jobs = []
  for idx in range(len(target_repositories)):
    target = target_repositories[idx]
    worker_project_name = "temp-project-%d" % (idx)
    proc = multiprocessing.Process(target=run_on_targets,
                                   args=(target, oss_fuzz_base,
                                         worker_project_name, idx, semaphore))
    jobs.append(proc)
    proc.start()

  for proc in jobs:
    proc.join()


def run_sequential(oss_fuzz_base, target_repositories):
  """Run auto-gen on a list of projects sequentially."""
  for idx in range(len(target_repositories)):
    target = target_repositories[idx]
    worker_project_name = "temp-project-%d" % (idx)
    run_on_targets(target, oss_fuzz_base, worker_project_name, idx)


def main():
  oss_fuzz_base = sys.argv[1]
  target = sys.argv[2]

  if os.path.isfile(target):
    target_repositories = read_targets_file(sys.argv[2])
  else:
    target_repositories = [target]
  print(target_repositories)

  use_multithreading = True
  if use_multithreading:
    run_parallels(oss_fuzz_base, target_repositories)
  else:
    run_sequential(oss_fuzz_base, target_repositories)


if __name__ == "__main__":
  main()
