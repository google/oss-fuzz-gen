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


def setup(oss_fuzz_base: str):
  temp_project_dir = os.path.join(oss_fuzz_base, "projects", "temp-project")
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
  subprocess.check_call("python3 infra/helper.py build_fuzzers temp-project",
                        shell=True,
                        cwd=oss_fuzz_base)


def run_autogen(github_url, outdir, openai_api_key, oss_fuzz_base):
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
      '%s/build/out/temp-project:/out' % (oss_fuzz_base),
      '-v',
      '%s/build/work/temp-project:/work' % (oss_fuzz_base),
      '-t',
      'gcr.io/oss-fuzz/temp-project',
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


def main():
  oss_fuzz_base = sys.argv[1]
  target = sys.argv[2]

  if os.path.isfile(target):
    targets = read_targets_file(sys.argv[2])
  else:
    targets = [target]

  print(targets)

  setup(oss_fuzz_base)
  openai_api_key = os.getenv("OPENAI_API_KEY")

  for idx in range(len(targets)):
    #if idx < 10:
    #    continue
    target = targets[idx]
    outdir = '/out/autogen-results-%d' % (idx)
    with open('status-log.txt', 'a') as f:
      f.write("Targeting: %s :: %d\n" % (target, idx))
    run_autogen(target, outdir, openai_api_key, oss_fuzz_base)


if __name__ == "__main__":
  main()
