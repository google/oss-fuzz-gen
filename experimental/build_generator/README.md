# OSS-Fuzz build set up creation

This directory holds logic for generating build scripts for projects
from scratch. The goal is to automatically create OSS-Fuzz projects
given a set of repositories as input, and then use these generated
OSS-Fuzz projects as input to OSS-Fuzz-gen's core harness generation logic.

The projects generated contain an empty fuzzer that can be used by
OFG's core harness generation. As such, there is no focus here on
actually generating harnesses, however, there is focus on creating a
building and linking script that includes relevant target code.


## Usage

```
git clone https://github.com/google/oss-fuzz-gen
cd oss-fuzz-gen
python3.11 -m virtualenv .venv
. .venv/bin/activate
python3 -m pip install -r requirements.txt

git clone https://github.com/google/oss-fuzz

echo "https://github.com/gregjesl/simpleson" > input.txt

python3 -m experimental.build_generator.runner -i input.txt -o generated-builds-0 -m ${MODEL} --oss-fuzz oss-fuzz
```

The above script will place generated builds in `generated-builds-0/oss-fuzz-projects`

The input file is a list of git repositories.

There can be 0-to-many build set ups per project. Each generated build may have
different characteristics, including the binary artifacts produced. This is, to some extend,
because it is impossible to know what the "real" artifacts should be, and each
project may be able to build in many different formats.