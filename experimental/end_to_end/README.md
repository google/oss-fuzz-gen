# End to end

Tools for generating a fuzzing infrastructure that has been validated and
tested from scratch, for a given GitHub repository. That is, this tool
takes as input a project URL and outputs a set of OSS-Fuzz projects
with fuzzing harnesses.

## Usage

```sh
git clone https://github.com/google/oss-fuzz-gen
cd oss-fuzz-gen
python3.11 -m virtualenv .venv
. .venv/bin/activate

git clone https://github.com/google/oss-fuzz

python3 -m experimental.end_to_end.cli --oss-fuzz oss-fuzz/ --input=../inp.txt --model=${MODEL} -o gen5
```