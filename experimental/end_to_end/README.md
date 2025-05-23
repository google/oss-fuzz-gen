# End to end

Tools for generating a fuzzing infrastructure that has been validated and
tested from scratch, for a given GitHub repository. That is, this tool
takes as input a project URL and outputs a set of OSS-Fuzz projects
with fuzzing harnesses.

## Usage

To run OSS-Fuzz project generation a CLI tool is exposed from
installing OSS-Fuzz-gen in a Python virtual environment. This is installed
using the following command:

```sh
# Set up virtual environment
python3.11 -m virtualenv .venv
. .venv/bin/activate

# Clone and install OSS-Fuzz-gen
git clone https://github.com/google/oss-fuzz-gen
cd oss-fuzz-gen
python3 -m pip install .
```

Upon installation of OSS-Fuzz-gen in the Python environment,
a CLI tool `oss-fuzz-generator` is made available that has
the following `help`:

```sh
$ oss-fuzz-generator --help
usage: oss-fuzz-generator [-h] {generate-builds,generate-fuzz-introspector-database,generate-harnesses,generate-full} ...

positional arguments:
  {generate-builds,generate-fuzz-introspector-database,generate-harnesses,generate-full}
    generate-builds     Generate OSS-Fuzz projects with build scripts but empty fuzzers.
    generate-fuzz-introspector-database
                        Generates a fuzz introspector database from auto build projects.
    generate-harnesses  Harness generation of OSS-Fuzz projects.
    generate-full       End to end generation of OSS-Fuzz projects.

options:
  -h, --help            show this help message and exit
```

`oss-fuzz-generator` makes several commands available, and the following
will iterate over these tools:


### End to end generation

**Generating OSS-Fuzz projects for a single repository**
The following example shows how to run the complete process of an 
OSS-Fuzz project generation.

```sh
# Use installed binary oss-fuzz-generator to create OSS-Fuzz project
echo "https://github.com/kgabis/parson" > input.txt
oss-fuzz-generator generate-full -m gpt-4o -i input.txt
...
$ ls final-oss-fuzz-projects/parson-agent/
build.sh  Dockerfile  empty-fuzzer.0.c  empty-fuzzer.1.c  empty-fuzzer.2.c  empty-fuzzer.3.c  empty-fuzzer.4.c  project.yaml
```

**Generating OSS-Fuzz projects for multiple repositories**
```sh
$ cat input.txt 
https://github.com/zserge/jsmn
https://github.com/rafagafe/tiny-json
$ tree final-oss-fuzz-projects/
final-oss-fuzz-projects/
├── jsmn-agent
│   ├── build.sh
│   ├── Dockerfile
│   ├── empty-fuzzer.0.c
│   ├── empty-fuzzer.1.c
│   ├── empty-fuzzer.2.c
│   ├── empty-fuzzer.3.c
│   ├── empty-fuzzer.4.c
│   ├── empty-fuzzer.5.c
│   ├── empty-fuzzer.6.c
│   ├── empty-fuzzer.7.c
│   └── project.yaml
└── tiny-json-agent
    ├── build.sh
    ├── Dockerfile
    ├── empty-fuzzer.0.c
    ├── empty-fuzzer.10.c
    ├── empty-fuzzer.11.c
    ├── empty-fuzzer.1.c
    ├── empty-fuzzer.2.c
    ├── empty-fuzzer.3.c
    ├── empty-fuzzer.4.c
    ├── empty-fuzzer.5.c
    ├── empty-fuzzer.6.c
    ├── empty-fuzzer.7.c
    ├── empty-fuzzer.8.c
    ├── empty-fuzzer.9.c
    └── project.yaml

2 directories, 26 files
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
