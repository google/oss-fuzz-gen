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
"""Holds templates used by the auto-generator both inside and outside the
OSS-Fuzz base builder."""

OSS_FUZZ_LICENSE = '''# Copyright 2024 Google LLC.
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
'''

EMPTY_OSS_FUZZ_BUILD = '''#!/bin/bash -eu
''' + OSS_FUZZ_LICENSE

BASE_DOCKER_HEAD = OSS_FUZZ_LICENSE + '''
FROM gcr.io/oss-fuzz-base/base-builder
RUN apt-get update && apt-get install -y make autoconf automake autopoint \\
                      libtool cmake pkg-config curl check libcpputest-dev \\
                      flex bison re2c
'''

CFLITE_TEMPLATE = '''name: ClusterFuzzLite PR fuzzing
on:
  workflow_dispatch:
  pull_request:
    branches: [ master ]
permissions: read-all
jobs:
  PR:
    runs-on: ubuntu-latest
    strategy:
      fail-fast: false
      matrix:
        sanitizer: [address]
    steps:
    - name: Build Fuzzers (${{ matrix.sanitizer }})
      id: build
      uses: google/clusterfuzzlite/actions/build_fuzzers@v1
      with:
        sanitizer: ${{ matrix.sanitizer }}
        language: c++
        bad-build-check: false
    - name: Run Fuzzers (${{ matrix.sanitizer }})
      id: run
      uses: google/clusterfuzzlite/actions/run_fuzzers@v1
      with:
        github-token: ${{ secrets.GITHUB_TOKEN }}
        fuzz-seconds: 100
        mode: 'code-change'
        report-unreproducible-crashes: false
        sanitizer: ${{ matrix.sanitizer }}
'''

# Empty CPP harness that is used to confirm compilation when generating
# auto-build scripts.
CPP_BASE_TEMPLATE = '''#include <stdint.h>
#include <iostream>

extern "C" int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    std::string input(reinterpret_cast<const char*>(data), size);

    // Insert fuzzer contents here
    // input string contains fuzz input.

    // end of fuzzer contents

    return 0;
}'''

# Empty C harness that is used to confirm compilation when generating
# auto-build scripts.
C_BASE_TEMPLATE = '''#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    printf("Hello world\\n");
    // Insert fuzzer contents here
    // input string contains fuzz input.

    // end of fuzzer contents

    return 0;
}'''

# Docker file used for starting the auto-gen workflow within an OSS-Fuzz
# base-builder image.
AUTOGEN_DOCKER_FILE = BASE_DOCKER_HEAD + '''
RUN rm /usr/local/bin/cargo && \\
 curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | bash -s -- -y && \\
 apt-get install -y cargo
RUN python3 -m pip install --upgrade pip
RUN python3 -m pip install --upgrade google-cloud-aiplatform
# Some projects may have recurisve modules from github without use of ssl,
# and this needs to be trusted. The below command can be removed if this
# project is not doing such.
RUN mkdir ~/.ssh && ssh-keyscan github.com >> ~/.ssh/known_hosts
COPY *.py *.json requirements.txt $SRC/
RUN python3 -m pip install -r $SRC/requirements.txt
COPY llm_toolkit $SRC/llm_toolkit
WORKDIR $SRC
RUN python3 -m pip install httpx==0.27.2
COPY build.sh $SRC/
'''

EMPTY_PROJECT_YAML = """homepage: "https://github.com/google/oss-fuzz"
language: c++
primary_contact: "info@oss-fuzz.com"
auto_ccs:
-
main_repo: 'https://github.com/google/oss-fuzz'
"""

# Docker file used for OSS-Fuzz integrations.
CLEAN_OSS_FUZZ_DOCKER = BASE_DOCKER_HEAD + ''' {additional_packages}
COPY *.sh $SRC/
RUN mkdir $SRC/fuzzers
COPY *.cpp *.c $SRC/fuzzers/
# Some projects may have recurisve modules from github without use of ssl,
# and this needs to be trusted. The below command can be removed if this
# project is not doing such.
RUN mkdir ~/.ssh && ssh-keyscan github.com >> ~/.ssh/known_hosts
RUN git clone --recurse-submodules {repo_url} {project_repo_dir}
WORKDIR $SRC/{project_repo_dir}
'''

CLEAN_DOCKER_CFLITE = BASE_DOCKER_HEAD + ''' {additional_packages}
COPY . $SRC/{project_repo_dir}
COPY .clusterfuzzlite/build.sh $SRC/build.sh
COPY .clusterfuzzlite/*.cpp $SRC/
COPY .clusterfuzzlite/*.c $SRC/
WORKDIR $SRC/{project_repo_dir}
'''

# Template file for building LLM prompt
LLM_PRIMING = '''<system>
You are a developer wanting to build a given C/C++ projects.
</system>'''

LLM_PROBLEM = '''
Here is a list of build system configuration files found from the target
repository. Please help generate the most suitable build script in bash to
build the project, assuming the build is done under Ubuntu 24 with all
necessary packages installed. Please also assume that the base script will
be executed under root privilege, thus no sudo command should be used. You
must only returns the content of the build script and nothing else more.

{BUILD_FILES}
'''

LLM_BUILD_FILE_TEMPLATE = '''
<file_path>{PATH}</file_path>
<file_content>{CONTENT}</file_content>
'''

LLM_RETRY = '''
I failed to build the project with the above provided build script.
Here is a dump of the stdout and stderr while executing the provided build
script. Please analyse the result and generate a new build script with the
same assumption above. You must only returns the content of the build script
and nothing else more as always.

Last 100 lines from the stdout for the execution:
{STDOUT}

Last 100 lines from the stderr for the execution:
{STDERR}
'''
