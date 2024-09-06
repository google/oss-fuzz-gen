# Auto-build OSS-Fuzz Projects from a GitHub Repository URL for Java Projects

This directory contains the logic for running auto-harness generation on projects
from scratch. This differs from the core OSS-Fuzz-gen, which focuses on enhancing
existing OSS-Fuzz projects. The logic in this folder is primarily geared towards
automatically creating build scripts and OSS-Fuzz projects from arbitrary code 
repositories.

[OSS-Fuzz from scratch including core OSS-Fuzz-gen](#OSS-Fuzz-from-scratch-
including-core-OSS-Fuzz-gen): Generating OSS-Fuzz projects from scratch using the
auto-harnessing in this folder and then applying core OSS-Fuzz-gen onto the
generated OSS-Fuzz project to produce a larger set of harnesses for a given project.

## Usage

```sh
# Prepare
# Vertex: Follow the steps at:
# https://github.com/google/oss-fuzz-gen/blob/main/USAGE.md#vertex-ai
export GOOGLE_APPLICATION_CREDENTIALS=PATH_TO_CREDS_FILE

# ChatGPT:
export OPENAI_API_KEY=your-api-key

# Prepare folder and set current working directory
git clone https://github.com/google/oss-fuzz-gen
cd oss-fuzz-gen/experimental/jvm

# Run end-to-end generation:
# 1) Create an OSS-Fuzz project
# 2) Extract additional harnesses using OSS-Fuzz-gen
MODEL=gpt-3.5-turbo TARGETS=https://github.com/jdereg/java-util ./run_e2e.sh

# You now have an auto-generated OSS-Fuzz project in workdir/auto-generated-projects
ls workdir/auto-generated-projects/
java-util

# Build the project using the OSS-Fuzz CLI
cd workdir/oss-fuzz
cp -rf ../auto-generated-projects/java-util projects/java-util
python3 infra/helper.py build_fuzzers java-util
```

## Overview of Auto-Generation

The core approach in this module involves the following steps:

1. An input in the form of comma-separated values for all target GitHub 
   repository URLs is provided to `generate_projects.py`.
2. Clone all target repositories, skipping any malformed or invalid URLs.
3. `generate_projects.py` analyses each target repository, determines the 
   build system of the project, and creates a temporary OSS-Fuzz project for 
   each target. Projects with unknown build systems are ignored (currently 
   supporting Maven, Gradle, and Ant).
4. An empty fuzzer is created, and a `build.sh` script is prepared to initiate 
   the building process of the detected build system. A `Dockerfile` and 
   `project.yaml` file are also generated.
5. Perform a Fuzz-Introspector build on all temporary OSS-Fuzz projects.
6. The output of Fuzz Introspector is loaded, providing data about all functions 
   in the compiled module. This data is used to create a local web app for 
   OSS-Fuzz-Gen to interact with.
7. OSS-Fuzz-Gen is invoked to generate targets on the local Fuzz Introspector 
   web app using the new analysis report.
8. The generated artefacts are organised into folders, each containing a 
   harness and the necessary files for full OSS-Fuzz integration.
