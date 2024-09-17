# Usage guide

Running an experiment requires three steps:
1. Install [dependencies](#Dependencies).
1. Setting up [LLM access](#LLM-Access).
3. Launch [experiment](#Running-Experiments).

## Prerequisites

### Dependencies
You must install:
1. Python 3.11
2. pip
3. python3.11-venv
4. Git
5. [Docker](https://www.docker.com/)
6. [Google Cloud SDK](https://cloud.google.com/sdk)
7. [c++filt](https://www.gnu.org/software/binutils/) must be available in PATH.
8. (optional for [`project_src.py`](./data_prep/project_src.py)) [clang-format](https://clang.llvm.org/docs/ClangFormat.html)

#### Python Dependencies
Install required dependencies in a `Python` virtual environment:
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### LLM Access
Setup [Vertex AI](#Vertex-AI) or [OpenAI](#OpenAI) with the following steps.

#### Vertex AI
Accessing Vertex AI models require a
[Google Cloud Project (GCP)](https://cloud.google.com/resource-manager/docs/creating-managing-projects#console)
with [Vertex AI enabled](https://cloud.google.com/vertex-ai/docs/start/cloud-environment).

Then auth to GCP:
```bash
gcloud auth login
gcloud auth application-default login
gcloud auth application-default set-quota-project <your-project>
```

You'll also need to specify the GCP projects and locations where you have Vertex AI quota (comma delimited):
```bash
export CLOUD_ML_PROJECT_ID=<gcp-project-id>
export VERTEX_AI_LOCATIONS=us-west1,us-west4,us-east4,us-central1,northamerica-northeast1
```

#### OpenAI

There are two ways to access OpenAI models.

1. [OpenAI API Key on OpenAI](#OpenAI-API-Key-on-OpenAI): This is the default way for using OpenAI models.

2. [OpenAI API Key on Azure](#OpenAI-API-Key-on-Azure): Please refer to this section if you are using **OpenAI models on Azure**.

##### OpenAI API Key on OpenAI

OpenAI requires an API key.

Then set it as an ENV variable:
```bash
export OPENAI_API_KEY='<your-api-key>'
```

##### OpenAI API Key on Azure

If your OpenAI API key is hosted on Azure, you need the specified Endpoint, API key, and the API version (optional).

Then set them as ENV variables:
```bash
export AZURE_OPENAI_API_KEY='<your-azure-api-key>'
export AZURE_OPENAI_ENDPOINT='<your-azure-endpoint>'
export AZURE_OPENAI_API_VERSION='<your-azure-api-version>' # default is '2024-02-01'
```

> Tip: 
To distinguish between the two ways of accessing OpenAI models, you need to add `-azure` to the model name **when using OpenAI on Azure**. For example, `gpt-3.5-turbo-azure` will use OpenAI on Azure, while `gpt-3.5-turbo` will use OpenAI on OpenAI.


## Running experiments
To generate and evaluate the fuzz targets in a benchmark set via *local* experiments:
```bash
./run_all_experiments.py \
    --model=<model-name> \
    --benchmarks-directory='./benchmark-sets/comparison' \
    [--ai-binary=<llm-access-binary>] \
    [--template-directory=prompts/custom_template] \
    [--work-dir=results-dir]
    [...]
# E.g., generate fuzz targets for TinyXML-2 with default template and fuzz for 30 seconds.
# ./run_all_experiments.py -y ./benchmark-sets/comparison/tinyxml2.yaml
```
where the `<model-name>` must be the name of one of the supported models. The
list of models supported by OSS-Fuzz-gen expands on a regular basis, and all
of the models can be listed with `run_all_experiments.py --help`. At the time
of writing the following models are supported, where `vertex` in the name means
the model is supported by way of Vertex AI:

1. `vertex_ai_code-bison`
2. `vertex_ai_code-bison-32k`
3. `vertex_ai_gemini-pro`
4. `vertex_ai_gemini-1-5-chat`
5. `vertex_ai_gemini-1-5`
6. `vertex_ai_gemini-experimental`
7. `vertex_ai_gemini-ultra`
8. `vertex_ai_claude-3-5-sonnet`
9. `vertex_ai_claude-3-opus`
10. `vertex_ai_claude-3-haiku`
11. `gpt-3.5-turbo-azure`
12. `gpt-3.5-turbo`
13. `gpt-4`
14. `gpt-4o`
15. `gpt-4o-azure`
16. `gpt-4-azure`

Experiments can also be run on Google Cloud using Google Cloud Build. You can
do this by passing
`--cloud <experiment-name> --cloud-experiment-bucket <bucket>`,
where `<bucket>` is the name of a Google Cloud Storage bucket your Google Cloud project.

### Benchmarks

In order to leverage LLMs for harness generation a set of code targets are needed.
In OFG terminology we consider these "benchmarks" and they are basically target functions
in a given OSS-Fuzz project or test-cases in a given OSS-Fuzz project. We need these
benchmarks to direct the auto-harness approach towards a specific part of some project.

We currently offer a variety of benchmark sets:

1. [`comparison`](./benchmark-sets/comparison): A small selection of OSS-Fuzz C/C++ projects.
2. [`all`](./benchmark-sets/all): All benchmarks across all OSS-Fuzz C/C++ projects.
3. [`c-specific`](./benchmark-sets/c-specific): A benchmark set focused on C projects.
4. [`from-test-large`](./benchmark-sets/from-test-large): A benchmark set comprising many test-cases for test-to-harness LLM generation.
5. [`from-test-small`](./benchmark-sets/from-test-small): A benchmark set used for test-to-harness generation, including a limited number of projects.
6. [`jvm-all`](./benchmark-sets/jvm-all): A large set of Java targets
7. [`jvm-medium`](./benchmark-sets/jvm-medium): A medium set of Java targets
8. [`jvm-small`](./benchmark-sets/jvm-small): A small set of Java targets
9. [`python-small`](./benchmark-sets/python-small): A small set of Python targets
10. [`test-and-func-mix`](./benchmark-sets/test-and-func-mix): A set of targets that mixes function-level targets and test-to-harness targets.
11. [`test-to-harness-jvm-small`](./benchmark-sets/test-to-harness-jvm-small): A small set of Java targets focused on test-to-harness generation.

### Visualizing Results
Once finished, the framework will output experiment results like this:
```
================================================================================
*<project-name>, <function-name>*
build success rate: <build-rate>, crash rate: <crash-rate>, max coverage: <max-coverage>, max line coverage diff: <max-coverage-diff>
max coverage sample: <results-dir>/<benchmark-dir>/fixed_targets/<LLM-generated-fuzz-target>
max coverage diff sample: <results-dir>/<benchmark-dir>/fixed_targets/<LLM-generated-fuzz-target>
```
where `<build-rate>` is the number of the fuzz targets that can compile over the total number of fuzz target generated by LLM (e.g., 0.5 if 4 out of 8 fuzz targets can build), `<crash-rate>` is the run-time crash rate, `<max-coverage>` measures the maximum line coverage of all targets, and `<max-coverage-diff>` shows the max **new** line coverage of LLM-generated targets against existing human-written targets in OSS-Fuzz.

Note that `<max-coverage>` and `<max-coverage-diff>` are computed based on the code linked against the fuzz target, not the whole project.
For example:
```
================================================================================
*tinyxml2, tinyxml2::XMLDocument::Print*
build success rate: 1.0, crash rate: 0.125, max coverage: 0.29099427381572096, max line coverage diff: 0.11301753077209996
max coverage sample: <result-dir>/output-tinyxml2-tinyxml2-xmldocument-print/fixed_targets/08.cpp
max coverage diff sample: <result-dir>/output-tinyxml2-tinyxml2-xmldocument-print/fixed_targets/08.cpp
```

#### Results report

To visualize these results via a web UI, with more details on the
exact prompts used, samples generated, and other logs, run:
```bash
python -m report.web -r <results-dir> -o <output-dir>
python -m http.server <port> -d <output-dir>
```
Where `<results-dir>` is the directory passed to `--work-dir` in your
experiments (default value `./results`).

Then navigate to `http://localhost:<port>` to view the result in [a table](#result-table).


## Detailed workflows
Configure and use framework in the following steps:
1. [Configure benchmark](#Configure-Benchmark)
2. [Setup prompt template](#Setup-Prompt-Templates)
3. [Generate fuzz target](#Generate-Fuzz-Target)
4. [Fix compilation error](#Fix-Compilation-Error)
5. [Evaluate fuzz target](#Evaluate-Fuzz-Target)
6. [Using local Fuzz Introspector instance](#Using-Local-Fuzz-Introspector-Instance)

### Configure Benchmark
Prepare a [benchmark YAML](data_prep/README.md#Benchmark-YAML) that specifies
the function to test, here is
[an example](benchmark-sets/comparison/tinyxml2.yaml). Follow the link above
to automatically generate one for a `C`/`C++` project in `OSS-Fuzz`. Note that
the project under test needs to be integrated into `OSS-Fuzz` to build.

### Setup Prompt Templates
Prepare [prompt templates](prompts/template_xml/).
The LLM prompt will be constructed based on the files in this directory. It
starts with a priming to define the main goal and important notices, followed
by some [example problems and solutions](data_prep/README.md#Fuzz-Target-Examples).
Each example problem is in the same format as the final problem (i.e., a
unction signature to fuzz), and the solution is the corresponding
human-written fuzz target for *different* functions from the same project or
other projects. Prompt can also include more information of the function (e.g.,
its usage, source code, or parameter type definitions), and model-specific
notes (e.g., common pitfalls to avoid).

You can pass an alternative template directory via `--template-directory`. The
new template directory does not have to include all files: The framework will
use files from `template_xml/` by default when they are missing. The default
prompt is structured as follows:
```
<Priming>
<Model-specific notes>
<Examples>
<Final question + Function information>
```

### Generate Fuzz Target
The script `run_all_experiments.py` will generate fuzz targets via LLM using
the prompt constructed above and measure their code coverage. All experiment
data will be saved into the `--work-dir`.

### Fix Compilation Error
When a fuzz target fails to build, the framework will automatically make five
attempts to fix it before terminate. Each attempt asks LLM to fix the fuzz
target based on the build failure from `OSS-Fuzz`, parses source code from the
response, and re-compiles it.

### Evaluate Fuzz Target
If the fuzz target compiles successfully, the framework fuzzes it with
`libFuzzer` and measures its line coverage. The fuzzing timeout is specified by
`--run-timeout` flag. Its line coverage is also compared against existing
human-written fuzz targets from `OSS-Fuzz` in production.

### Using Local Fuzz Introspector Instance

OSS-Fuzz-gen relies on [Fuzz Introspector](https://github.com/ossf/fuzz-introspector)
to extract information about the projects under analysis. This is done by querying
[https://introspector.oss-fuzz.com](https://introspector.oss-fuzz.com) which
offers a set of APIs to inspect OSS-Fuzz projects in a programmatic way.

It may be suited to run a local version of the Fuzz Introspector web application
instead of directly querying [https://introspector.oss-fuzz.com](https://introspector.oss-fuzz.com).
This can be useful in scenarios such as testing extension to OSS-Fuzz-gen that
requires new program analysis data, network bandwidth needs to be limited or perhaps
the website is down. It's possible to set OSS-Fuzz-gen to use a local version
of [https://introspector.oss-fuzz.com](https://introspector.oss-fuzz.com) by
passing the `-e` flag to `run_all_experiments.py`. However, in order to do this,
a local instance of the Fuzz Introspector endpoint will first need to be
initialized locally. This is simple to do and we reference the Fuzz Introspector
guide [here](https://github.com/ossf/fuzz-introspector/tree/main/scripts/oss-fuzz-gen-e2e#usage) for this.


## Development


## Contribution process

### Development environment

#### Auto Format / Lint
You can a Git pre-push hook to auto-format/-lint your code:

```bash
./helper/add_pre-push_hook
```

Or manually run the formater/linter by running:

```bash
.github/helper/presubmit
```

#### Updating Dependencies

We use https://github.com/jazzband/pip-tools to manage our Python dependencies.

```bash
# Edit requirements.in
pip install pip-tools  # Required to re-generate requirements.txt from requirements.in
pip-compile requirements.in > requirements.txt
pip install -r requirements.txt
```

