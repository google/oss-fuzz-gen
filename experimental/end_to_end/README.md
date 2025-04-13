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

echo "https://github.com/kgabis/parson" > input.txt

python3 -m experimental.end_to_end.cli --input=input.txt --model=${MODEL}
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
