# Run OSS-Fuzz-gen on a new OSS-Fuzz project

This folder contains logic for running OSS-Fuzz-gen on a new OSS-Fuzz project.
A new OSS-Fuzz project in this case means a project where you have developed a
proper OSS-Fuzz project that works locally, but the project is not part of
upstream OSS-Fuzz.

This serves two purposes:

1) For development purposes. This approach is useful for developing target code
   bases with specific attributes that you want to test LLM harness generation
   against. As such, it's an environment that is meant to make it easy to test
   approaches and benchmark code patterns against your prompt generator/LLM.


2) Help in the OSS-Fuzz project development generation by leveraging the powers
   of OSS-Fuzz-gen to create harnesses for you.
   
   
## Usage

The following commands show a sample of how to use the logic of this folder.

### Set up OSS-Fuzz-gen

In the event you haven't already set up OSS-Fuzz-gen, you can use the following
steps:

```sh
# Set up OSS-Fuzz-gen
git clone https://github.com/google/oss-fuzz-gen
cd oss-fuzz-gen
BASE_OFG=$PWD

python3.11 -m virtualenv .venv
. .venv/bin/activate
python3 -m pip install -r requirements.txt
```


### Run OSS-Fuzz-gen on new project
The following assumes you are already in a virtual environment
with OSS-Fuzz requirements installed.
 
```sh
BASE_OFG=$PWD
# To start, you need to specify which model you will
# be using for the experiments. You need to set the MODEL
# environment variable now.

# Create a working set up.
./scripts/run-new-oss-fuzz-project/setup.sh

# Create an OSS-Fuzz project that will be used for the experiment.
cd work/oss-fuzz/projects
git clone https://github.com/AdaLogics/oss-fuzz-auto

cd $BASE_OFG

# Now run our the generation on our newly created OSS-Fuzz project.
./scripts/run-new-oss-fuzz-project/run-project.sh oss-fuzz-auto

# Once finished, check results
python3 -m report.web -r results -s

# Navigate to localhost:8012
```