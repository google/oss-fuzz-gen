# Auto-build oss-fuzz projects from a GitHub repo URL


## Overview

The core part of approach in this module takes the following steps:

1) An input in the form of a GitHub repo is given to `runner.py`.
2) `runner.py` creates a temporary OSS-Fuzz project that contains
  `build-generator.py` and builds the project's respective OSS-Fuzz base
  builder image.
3) `runner.py` launches the Project's OSS-Fuzz base-builder image of the
  temporary project with `build-generator.py` as entrypoint.

`build-generator.py` will then proceed to carry out the following tasks within
the project's OSS-Fuzz base-builder Docker container:

4) clone the input repository
5) Scan the files of the repository to create suggested builds. This involves
  looking for build files, e.g. `Makefile` and `CMakeLists.txt`, and then
  creating a set of (`AutoBuildContainer`) possible commands that may be able
  to build the project, we call these auto-build container objects.
6) For each auto-build container object created, a build is performed of the
  target project using the identified commands. This is done by creating a
  `build.sh` script and running `compile` inside the OSS-Fuzz image. Because
  `compile` is used, this means that `ASAN` is used during the build. If the
  build succeeds, then scan of the build folder is made to identify the list of
  static archives produced by the build.
  Additionally, each folder with a `.h` file is saved, as this
  will later be used when linking in a fuzzer.
7) An empty fuzzer is created and a `build.sh` is prepared to link the empty
  fuzzer to the static libraries. This is then run using `compile` to verify
  that linking to the static libraries won't cause complications.
8) For each auto-build that succeeded in producing one or more `.a` files an
  Fuzz Introspector build is prepared. This specifically means another
 `build.sh` script is prepared albeit this time with the sanitizer
  set to INTROSPECTOR. Then, another `compile` is run, which also includes
  various Fuzz Introspector settings that tells Fuzz Introspector to perform as
  much analysis as possible.
9) The output of Fuzz Introspector is loaded, meaning the analysis now has
 data about all functions in the module compiled. The Fuzz Introspector data
 is then passed to fuzz generation heuristics, which can use the data however
 they like. The analysis now asks the fuzz heuristics (currently 4) to generate
 fuzzer source code for X amount of functions.
10) For each produced harness a `build.sh` is created that will run the build
 commands identified and link in the harness created. This is the final step
 for building the harness, and the specific artifacts used at this point
 are (0) build commands identified during auto-build; (1) static libraries
 identified during auto-build; (2) include directories identified during
 auto-build; (3) fuzzer source code produced by the generation heuristics.
11) The harness is run for a short amount of time and is logged.
12) The artifacts are wrapped in a folder such that each folder has a harness,
 build script and logs for building/running.


The algorithm takes the arguments:
1) Target repository
2) Number of functions to target

This means the total amount of build/harness configurations to perform is:

N x B x G where:

- N is the number of functions to target
- B is the number of build heuristics succeeding (max 10 or so at this point)
- G is the number of harness generator heuristics, which is 4 at this point.


For example, if we specify 20 best functions to be targeted for auto
harnessing, and 5 build heuristics succeed in building one or more static
libraries, then we will end up trying to build/run 400 harnesses.


## Usage

```sh
# Prepare
# Vertex: Follow the steps at:
# https://github.com/google/oss-fuzz-gen/blob/main/USAGE.md#vertex-ai
export export GOOGLE_APPLICATION_CREDENTIALS=PATH_TO_CREDS_FILE

# chatgpt:
export OPENAI_API_KEY=your-api-key
git clone https://github.com/google/oss-fuzz /tmp/oss-fuzz-10

git clone https://github.com/google/oss-fuzz-gen
cd oss-fuzz-gen/from-repo/c-cpp
python3 ./runner.py -o ~/tmp/oss-fuzz-10 -t 15 -i TARGET_REPO_URL -m vertex

# Use "-m openai" for chatgpt above
```

# Trophies

Here we list a set of trophies based of this approach. Since we generate both
OSS-Fuzz and ClusterFuzzLite integrations we highlight for each trophy which
type was submitted to the upstream repository.

| GitHub repository | Type | PR | Issues |
| ----------------- | ---- | -- | ------ |
| https://github.com/gregjesl/simpleson | ClusterFuzzLite | [40](https://github.com/gregjesl/simpleson/pull/40) | [39](https://github.com/gregjesl/simpleson/pull/39) |
| https://github.com/memononen/nanosvg | OSS-Fuzz | [11944](https://github.com/google/oss-fuzz/pull/11944) | |
| https://github.com/skeeto/pdjson | ClusterFuzzLite | [33](https://github.com/skeeto/pdjson/pull/33)  | |
| https://github.com/kgabis/parson | ClusterFuzzLite | [214](https://github.com/kgabis/parson/pull/214) | |
| https://github.com/rafagafe/tiny-json | ClusterFuzzLite | [18](https://github.com/rafagafe/tiny-json/pull/18) | |
| https://github.com/kosma/minmea | ClusterFuzzLite | [79](https://github.com/kosma/minmea/pull/79) | |
| https://github.com/marcobambini/sqlite-createtable-parser | ClusterFuzzLite | [5](https://github.com/marcobambini/sqlite-createtable-parser/pull/5) | [6](https://github.com/marcobambini/sqlite-createtable-parser/pull/6) |
| https://github.com/benoitc/http-parser | ClusterFuzzLite | [102](https://github.com/benoitc/http-parser/pull/102) | [103](https://github.com/benoitc/http-parser/pull/103) |
| https://github.com/orangeduck/mpc | ClusterFuzzLite | [169](https://github.com/orangeduck/mpc/pull/169) | |
| https://github.com/JiapengLi/lorawan-parser | ClusterFuzzLite | [17](https://github.com/JiapengLi/lorawan-parser/pull/17) | |
| https://github.com/argtable/argtable3 | ClusterFuzzLite | [96](https://github.com/argtable/argtable3/pull/96) | |
| https://github.com/h2o/picohttpparser | ClusterFuzzLite | [83](https://github.com/h2o/picohttpparser/pull/83) | |
| https://github.com/ndevilla/iniparser | ClusterFuzzLite | [161](https://github.com/ndevilla/iniparser/pull/161) | |
| https://github.com/codeplea/tinyexpr | ClusterFuzzLite | [114](https://github.com/codeplea/tinyexpr/pull/114) | |
| https://github.com/vincenthz/libjson | ClusterFuzzLite | [28](https://github.com/vincenthz/libjson/pull/28) | |
