# Data Preparation

This directory help you prepare three kinds of data to benefit fuzz target generation:
1. [Benchmark YAML](#Benchmark-YAML)
2. [Fuzz target examples](#Fuzz-Target-Examples)
3. [Training data](#Training-Data)

## Benchmark YAML
A benchmark YAML file (e.g.,
[`tinyxml2.yaml`](../benchmark-sets/comparison/tinyxml2.yaml)) is required
for fuzz target generation, it specifies `functions`, `project`, `target_path`,
  and optionally `target_name`:
* `functions` lists the signatures of the function to generate fuzz targets.
* `project` is the name of open-source project in `OSS-Fuzz` (e.g.,
  [`TinyXML-2`](https://github.com/google/oss-fuzz/tree/master/projects/tinyxml2))
that contains `functions`.
* `target_path` is the path to an existing fuzz target in [the `project`'s `OSS-Fuzz` container](https://google.github.io/oss-fuzz/getting-started/new-project-guide/#dockerfile). It will be replaced with the LLM-generated target and built for fuzzing evaluation.
* `target_name` is an *optional* field to specify the fuzz target binary name.
  It is required when the binary name is different from the basename of
  `target_path`, e.g., in
  [`libpng-proto`](../benchmark-sets/origin_benchmarks/libpng-proto.yaml#18).

### Generation
Use [`introspector.py`](introspector.py) to generate a YAML file of a `C`/`C++` project in `OSS-Fuzz`:
```
# In virtual env under root directory.
python -m data_prep.introspector <project-name> -m <num_benchmark_per_project> -o <output_dir>
# E.g., python -m data_prep.introspector tinyxml2 -m 5 -o benchmark-sets/new
```

Benchmark files generated in this way prioritize [far-reach-but-low-coverage](https://introspector.oss-fuzz.com/api#api-far-reach-but-low-coverage) functions in `OSS-Fuzz` production, hence easier to achieve higher [`max line coverage diff`](../README.md#Visualizing-Results).

## Fuzz Target Examples
The framework adds existing human-written fuzz targets as examples into the
prompt to improve result quality. Our experiments show that using human-written
fuzz targets (even though for different functions) from the same project can
give more project-specific context to LLM, while using targets from a different
project reduces over-fitting.

Each example consists of a problem and a solution. The solution contains a
human-written fuzz target from `OSS-Fuzz` that is proven to be productive. It
is in the same format as the response we expect from LLM. The problem contains
the signature of a function in the result fuzz target. Similarly, it is in the
same format as the final question for LLM.

### Generation
The examples are **automatically** added into prompts via `generate_data()` in [`project_targets.py`](project_targets.py).

Use [`project_src.py`](project_src.py) to retrieve all fuzz target files of a `C`/`C++` project in `OSS-Fuzz` to a local directory (`example_targets/<project_name>`, by default):
```
# In virtual env under root directory.
python -m data_prep.project_src -p <project-name>
# E.g., retrieve all human-written fuzz targets for TinyXML-2:
# python -m data_prep.project_src -p tinyxml2
# E.g., retrieve all fuzz targets for all projects:
python -m data_prep.project_src -p all
```

## Training Data
We provide ways to generate training data for model fine-tuning or Parameter
Efficient Tuning (PET). The training data contains a list of 2-item-sublists,
with function signature and the corresponding fuzz target being the first and
second item in the sublist. Since a fuzz targets may test multiple functions,
multiple `function_signature`s may share the same `fuzz_target`, i.e.:
```
[
  [<function_signature_1>, <fuzz_target_1>],
  [<function_signature_2>, <fuzz_target_2>],
  [<function_signature_3>, <fuzz_target_2>],
]
```

### Generation
Use [`project_targets.py`](project_targets.py) to generate a JSON file based on a `C`/`C++` project in `OSS-Fuzz`:
```
# In virtual env under root directory.
python -m data_prep.project_targets --project-name <project-name>
# E.g., generate data for TinyXML-2:
# python -m data_prep.project_targets --project-name tinyxml2
# E.g., generate data for all C/C++ projects:
# python -m data_prep.project_targets --project-name all
```
