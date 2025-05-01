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

OSS_FUZZ_LICENSE = '''# Copyright 2025 Google LLC.
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
                      flex bison re2c protobuf-compiler uuid uuid-dev
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
# Disable light for now. This is to speed up performance and we currently
# do not use light during build generation.
# TODO(David): enable this and make sure performance is too
# exhaustive (100+ min for some projects)
ENV FI_DISABLE_LIGHT=1
COPY *.py *.json $SRC/
RUN python3 -m pip install pyyaml
WORKDIR $SRC
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
RUN mkdir -p {fuzzer_dir}
COPY *.cpp *.c {fuzzer_dir}
# Some projects may have recurisve modules from github without use of ssl,
# and this needs to be trusted. The below command can be removed if this
# project is not doing such.
RUN mkdir ~/.ssh && ssh-keyscan github.com >> ~/.ssh/known_hosts
# Disable light for now. This is to speed up performance and we currently
# do not use light during build generation.
# TODO(David): enable this and make sure performance is too
# exhaustive (100+ min for some projects)
ENV FI_DISABLE_LIGHT=1
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
You are tasked with generating a fuzzing harness and build script to fuzz a target project. Use the provided build system files to compile the project and link it with the fuzzing harness.

### Output Format
Your response **must only contain two XML tags**:
- `<bash></bash>`: Wraps the complete Bash build script for compiling both the target project and the fuzzing harness.
- `<fuzzer></fuzzer>`: Wraps the full fuzzing harness source code, modified to include and link the compiled target project.

### Build Script Instructions
- The build script will be executed as root on **Ubuntu 24.04**, so **do not use `sudo`**.
- `$CC` and `$CXX` are set and must be used for compilation.
- `$CFLAGS` and `$CXXFLAGS` must be used for compilation of source files. This is important because we need the flags to be used in the environment.
- The fuzzing harness binary must be placed as `$OUT/{FUZZER_NAME}`. Make sure to use `-o $OUT/{FUZZER_NAME}` in the link stage of the fuzzing harness
- If additional packages are needed, include a single `apt install` command at the top.
- Use the provided build system files to compile the target project.
- If a static library is not produced, collect the object files and archive them using `llvm-ar`.
- Do **not** modify existing build configuration files (e.g., via `sed`).
- Avoid running tests or install targets—only compilation is required.
- Ensure environment variables are handled as follows:
  ```bash
  if [ -z "${CFLAGS:-}" ]; then
    CFLAGS="-I/some/include"
  else
    CFLAGS="$CFLAGS -I/some/include"
  fi
  ```
- Ensure the fuzzing harness is linked with the target project using:
  ```bash
  -Wl,--whole-archive libtarget.a -Wl,--no-whole-archive
  ```

### Fuzzing Harness Instructions
- Modify the provided fuzzing harness (`$SRC/{FUZZING_FILE}`) to include relevant headers from the target project.
- Include appropriate header files from the list below.

### Provided Resources
- **Build system configuration files:**
  <build_files>
  {BUILD_FILES}
  </build_files>

- **Dockerfile for build environment:**
  <dockerfile>
  {DOCKERFILE}
  </dockerfile>

- **Template fuzzing harness:**
  <fuzzer>
  {FUZZER}
  </fuzzer>

- **Available header files:**
  <headers>
  {HEADERS}
  </headers>
'''

LLM_BUILD_FILE_TEMPLATE = '''
<file_path>{PATH}</file_path>
<file_content>{CONTENT}</file_content>
'''

LLM_RETRY = '''
I failed to build the project with the above provided build script.
Please analyse the result and generate a new build script with the same assumption above.
You must only returns the content of the build script and nothing else more as always.
Your output must contain only two XML tags:
<bash></bash> – wraps the complete build script for both the target project and the fuzzing harness.
<fuzzer></fuzzer> – wraps the complete, modified fuzzing harness, which includes and links the binaries compiled from the target project.

Here is a dump of the bash execution result.
{BASH_RESULT}
'''

LLM_AUTO_DISCOVERY = '''
You are tasked with generating a **build script** to compile and statically link a target project, and updating a **template fuzzing harness** by including relevant project headers. Do **not** modify the harness logic, only add `#include` statements.

The source code is located at `$SRC/{PROJECT_NAME}` inside a Docker container running **Ubuntu 24.04**. The fuzzing harness template is at `$SRC/{FUZZING_FILE}` and is provided below.

The generated build script will be executed in a **fresh session for testing**. Do **not** include any `|| true` or similar constructs to suppress errors.

### Environment Details

- Operating system: Ubuntu 24.04 (Docker)
- Compiler: Use `$CC` and `$CXX` for all compilation and linking
- `$CFLAGS` and `$CXXFLAGS` must be used for compilation of source files. This is important because we need the flags to be used in the environment.
- Project source: `$SRC/{PROJECT_NAME}`
- Fuzzing harness template: `$SRC/{FUZZING_FILE}`
- Linking: Use `$LIB_FUZZING_ENGINE` and link fuzzers statically
- Output fuzzers to: `$OUT/{FUZZER_NAME}`

### Provided Resources

- Dockerfile:
  <dockerfile>
  {DOCKERFILE}
  </dockerfile>

- Template fuzzing harness:
  <fuzzer>
  {FUZZER}
  </fuzzer>

### Interaction Protocol

This is an **interactive process**. You do not initially know the project layout or build system. You must request commands to be run inside the Docker container to discover this information.

You are limited to **{MAX_DISCOVERY_ROUND} discovery rounds**, so plan efficiently.

Your result must only contains these XML tags. **NOTHING MORE**.
- `<command></command>` – Use to request shell commands that will be executed in the container. You may include multiple semicolon-separated commands per tag, or use multiple tags.
- `<bash></bash>` – Use only when ready to output the **final build script**.
- `<fuzzer></fuzzer>` – wraps the complete, modified fuzzing harness, which includes and links the binaries compiled from the target project. The result **MUST** contain the **entire source code** of the updated fuzzing harness, not just a diff or partial snippet.

Your goal is to compile the project into a static library (`libtarget.a`) that can be linked into the fuzzing harnesses.

### Supported Build Systems (Follow This Order Strictly)

Always follow the order below **in strict priority** when determining how to build the project.
Use the **first applicable method** — only fall back to later options if the earlier ones are not present or not usable. Known build systems always take precedence.

1. **General Build Systems (Preferred)**
   If the project contains standard build files for any common C/C++ build system (e.g., `Makefile`, `configure`, etc), use the corresponding build system directly.
   Do **not** patch, modify, or override these files in any way.

2. **BUILD.gn (GN/Ninja Build System)**
   - Attempt to use `gn` and `ninja` directly:
     ```bash
     apt update && apt install -y ninja-build
     # Install gn manually or from source if needed.
     ```
   - If direct use of GN/Ninja is not feasible, fall back to **manual parsing** of `BUILD.gn`:
     - Extract `sources`, `include_dirs`, and `defines`.
     - Compile using `$CC`/`$CXX` and apply `$CFLAGS`/`$CXXFLAGS`.
     - Archive object files with `llvm-ar`.
     - Install any required packages listed in `BUILD.gn`.

3. **Android.bp (Soong Build System)**
   - Do **not** invoke Android-specific build tools (e.g., `soong_ui.bash`, `m`, `envsetup.sh`).
   - Treat `Android.bp` as a declarative build description.
   - Manually parse it to:
     - Extract `srcs`, `include_dirs`, `header_libs`, and `static_libs`.
     - Use this information to compile sources with `$CC`/`$CXX` and archive with `llvm-ar`.
     - Resolve `static_libs` by checking https://android.googlesource.com/platform/external for corresponding modules and building them as described above.

4. **No Build System Found (Manual Compilation Fallback)**
   This is the **last resort**. Use this only if **none of the above build systems are present or usable**:
   - Use `find` or similar tools to discover all relevant `.c`/`.cc` files.
   - Compile them manually with `$CC`/`$CXX`, applying `$CFLAGS`/`$CXXFLAGS`.
   - Archive object files into a static library using `llvm-ar`.

**Do not skip or bypass earlier build system options**. Always follow the order above. If a known build system is found (e.g., `Makefile`, `BUILD.gn`, or `Android.bp`), it must take precedence over manual compilation.

Additionally:

- Use `$CFLAGS` and `$CXXFLAGS` in all compilation steps.
- Always install any required system packages via `apt-get`.

### Build Script Requirements

- Use `$CC` and `$CXX` for all compilation and linking tasks.
- Always apply `$CFLAGS` and `$CXXFLAGS` when compiling source files, both for the project and the fuzzing harness. Safely extend these variables only if needed. If specific include paths are required, add them like this (replace `/some/include` with the actual path as appropriate):
  ```bash
  if [ -z "${CFLAGS:-}" ]; then
    CFLAGS="-I/some/include"
  else
    CFLAGS="$CFLAGS -I/some/include"
  fi
  ```
- **Do not forcibly include standard system headers** (e.g., with `-include sys/types.h`, `-include stdint.h`, or `-include linux/types.h`) via `CFLAGS` or `CXXFLAGS`, as this may lead to conflicting type definitions and compilation errors.

- **Avoid modifying `CFLAGS` or `CXXFLAGS` unless necessary**. Inherit and extend them only when required for a specific build constraint.

- The script **MUST NOT**:
  - Use `sudo` (the container runs as root),
  - Suppress errors (e.g., via `|| true`),

- If possible, please exclude the building of tests or examples.

- If the build does not automatically generate a static library, collect all `.o` files and manually archive them:
  ```bash
  llvm-ar rcs libtarget.a *.o
  ```

- When linking the fuzzing harness, always use:
  ```bash
  -Wl,--whole-archive libtarget.a -Wl,--no-whole-archive
  ```

- Ensure the script builds **all fuzzing harnesses** matching the `empty-fuzzer.*` pattern using a loop, like so:
  ```bash
  for fuzzer in $(find $SRC -maxdepth 1 -name 'empty-fuzzer.*'); do
    fuzzer_basename=$(basename $fuzzer)
    $CC $CFLAGS -I$SRC/... $fuzzer -o $OUT/${fuzzer_basename} -L. -Wl,--whole-archive libtarget.a -Wl,--no-whole-archive $LIB_FUZZING_ENGINE
  done
  ```

- If you are not using a build system (e.g., Make/CMake), and some source files fail to compile, you may **skip those individual files** to allow the build process to complete successfully. Focus on compiling as many valid source files as possible to produce a usable static library.

### Fuzzing Harness Requirements

- Only modify the harness by adding necessary `#include` statements for project headers. Try to keep it as minimum as possible.
- Do not alter or add logic, boilerplate, or functions.
- The result MUST be **a complete, valid C/C++ file** that compiles and links cleanly.

### Getting Started

Begin with discovery commands to examine project structure and identify build system and headers.

Useful starting points:
```bash
ls -la $SRC/{PROJECT_NAME}
find $SRC/{PROJECT_NAME} -name Android.bp -o -name BUILD.gn -o -name Makefile -o -name CMakeLists.txt
find $SRC/{PROJECT_NAME} -type f \\( -name '*.h' -o -name '*.hpp' \\)
```

Your **first reply** must be a `<command>` block to begin project exploration.
Your **final reply** must include the `<bash>` block and, if the harness was modified, the `<fuzzer>` block.
'''

LLM_DOCKER_FEEDBACK = '''
Here is the result of that command execution:

{RESULT}
'''

LLM_NO_VALID_TAG = '''
Your previous response is invalid.

To be valid, the response must meet the following requirements regarding XML tags:

- At least one of the following must be present:
  - One or more <command></command> tags containing valid shell commands.
  - A single <bash></bash> tag containing the complete Bash build script for compiling both the target project and the fuzzing harness.

- The <fuzzer></fuzzer> tag is **required only if** the fuzzing harness has been modified. If included, it must contain the **entire source code** of the updated fuzzing harness, not just a diff or partial snippet.

Do not include any content outside these XML tags. Revisit your output and regenerate it with these rules strictly followed.
'''

LLM_MISSING_BINARY = '''
The compiled binary was not found at `$OUT/{FUZZER_NAME}`. Please ensure that you use `-o $OUT/{FUZZER_NAME}` during the linking stage of the fuzzing harness.

Below is the output from executing the previously generated build script for reference:

{RESULT}
'''
