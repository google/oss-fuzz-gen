# A Framework for Fuzz Target Generation and Evaluation

This framework generates fuzz targets for real-world `C`/`C++/Java/Python` projects with
various Large Language Models (LLM) and benchmarks them via the
[`OSS-Fuzz` platform](https://github.com/google/oss-fuzz).

More details available in [AI-Powered Fuzzing: Breaking the Bug Hunting Barrier](https://security.googleblog.com/2023/08/ai-powered-fuzzing-breaking-bug-hunting.html):
![Alt text](images/Overview.png "Overview")

Current supported models are:
- Vertex AI code-bison
- Vertex AI code-bison-32k
- Gemini Pro
- Gemini Ultra
- Gemini Experimental
- Gemini 1.5
- OpenAI GPT-3.5-turbo
- OpenAI GPT-4
- OpenAI GPT-4o
- OpenAI GPT-4o-mini
- OpenAI GPT-4-turbo
- OpenAI GPT-3.5-turbo (Azure)
- OpenAI GPT-4 (Azure)
- OpenAI GPT-4o (Azure)

Generated fuzz targets are evaluated with four metrics against the most up-to-date data from production environment:
- Compilability
- Runtime crashes
- Runtime coverage
- Runtime line coverage diff against existing human-written fuzz targets in `OSS-Fuzz`.

Here is a sample experiment result from 2024 Jan 31.
The experiment included [1300+ benchmarks](./benchmark-sets/all) from 297 open-source projects.

![image](https://github.com/google/oss-fuzz-gen/assets/759062/fa53698b-e44c-4b58-b5e7-798337c8b752)

Overall, this framework manages to successfully leverage LLMs to generate valid fuzz targets (which generate non-zero coverage increase)
for 160 C/C++ projects. The maximum line coverage increase is 29% from the existing human-written targets.

Note that these reports are not public as they may contain undisclosed vulnerabilities. 

## Usage

Check our detailed [usage guide](./USAGE.md) for instructions on how to run this framework and generate reports based on the results.

## Collaborations
Interested in research or open-source community collaborations?
Please feel free to create an issue or email us: oss-fuzz-team@google.com.

<img src="images/Collaboration.png" width="200" height="200">

## Bugs Discovered

So far, we have reported 30 new bugs/vulnerabilities found by automatically generated targets built
by this framework:
| Project |    Bug    |    LLM    | Prompt Builder | Target oracle |
| ------- | --------- | --------- | --------------- | ------- |
| [`cJSON`](https://github.com/google/oss-fuzz/tree/master/projects/cjson) | [OOB read](https://github.com/DaveGamble/cJSON/issues/800) | Vertex AI | [Default](prompts/template_xml) | Far reach, low coverage |
| [`libplist`](https://github.com/google/oss-fuzz/tree/master/projects/libplist) | [OOB read](https://github.com/libimobiledevice/libplist/issues/244) | Vertex AI | [Default](prompts/template_xml) | Far reach, low coverage |
| [`hunspell`](https://github.com/google/oss-fuzz/tree/master/projects/hunspell) | [OOB read](https://github.com/hunspell/hunspell/issues/996) | Vertex AI | [default](prompts/template_xml) | Far reach, low coverage |
| [`zstd`](https://github.com/google/oss-fuzz/tree/master/projects/zstd) | [OOB write](https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=67497) | Vertex AI | [default](prompts/template_xml) | Far reach, low coverage |
| [`gdbm`](https://github.com/google/oss-fuzz/tree/master/projects/gdbm) | [Stack buffer underflow](https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=67483) | Vertex AI | [default](prompts/template_xml) | Far reach, low coverage |
| [`hoextdown`](https://github.com/google/oss-fuzz/tree/master/projects/hoextdown) | [Use of uninitialised memory](https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=67516) | Vertex AI | [default](prompts/template_xml) | Far reach, low coverage |
| [`pjsip`](https://github.com/google/oss-fuzz/tree/master/projects/pjsip) | [OOB read](https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=71356) | Vertex AI | [Default](prompts/template_xml) | Low coverage with fuzz keyword + easy params far reach |
| [`pjsip`](https://github.com/google/oss-fuzz/tree/master/projects/pjsip)  | [OOB read](https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=71357) | Vertex AI | [Default](prompts/template_xml) | Low coverage with fuzz keyword + easy params far reach |
| [`gpac`](https://github.com/google/oss-fuzz/tree/master/projects/gpac) | [OOB read](https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=71358) | Vertex AI | [Default](prompts/template_xml) | Low coverage with fuzz keyword + easy params far reach |
| [`gpac`](https://github.com/google/oss-fuzz/tree/master/projects/gpac)  | [OOB read/write](https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=71542) | Vertex AI | [Default](prompts/template_xml) | All |
| [`gpac`](https://github.com/google/oss-fuzz/tree/master/projects/gpac)  | [OOB read](https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=71543) | Vertex AI | [Default](prompts/template_xml) | All |
| [`gpac`](https://github.com/google/oss-fuzz/tree/master/projects/gpac)  | [OOB read](https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=71544) | Vertex AI | [Default](prompts/template_xml) | All |
| [`sqlite3`](https://github.com/google/oss-fuzz/tree/master/projects/sqlite3) | [OOB read](https://issues.oss-fuzz.com/issues/42538590) | Vertex AI | [Default](prompts/template_xml) | All |
| [`htslib`](https://github.com/google/oss-fuzz/tree/master/projects/htslib) | [OOB read](https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=71740) | Vertex AI | [Default](prompts/template_xml) | All |
| [`libical`](https://github.com/google/oss-fuzz/tree/master/projects/libical) | [OOB read](https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=71741) | Vertex AI | [Default](prompts/template_xml) | All |
| [`croaring`](https://github.com/google/oss-fuzz/tree/master/projects/croaring) | [OOB read](https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=71738) | Vertex AI | [Test-to-harness](prompts/template_xml) | All |
| [`openssl`](https://github.com/google/oss-fuzz/tree/master/projects/openssl) | [CVE-2024-9143](https://www.cve.org/CVERecord?id=CVE-2024-9143) - [OOB read/write](https://g-issues.oss-fuzz.com/issues/42538437) | Vertex AI | [Default](prompts/template_xml) | All |
| [`liblouis`](https://github.com/google/oss-fuzz/tree/master/projects/liblouis)] | [Use of uninitialised memory](https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=71354) | Vertex AI | Test-to-harness | Test identifier |
| [`libucl`](https://github.com/google/oss-fuzz/tree/master/projects/libucl) | [OOB read](https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=71359) | Vertex AI | [Default](prompts/template_xml) | Low coverage with fuzz keyword + easy params far reach |
| [`openbabel`](https://github.com/google/oss-fuzz/tree/master/projects/openbabel) | [Use after free](https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=71360) | Vertex AI | [Default](prompts/template_xml) | Low coverage with fuzz keyword + easy params far reach |
| [`libyang`](https://github.com/google/oss-fuzz/tree/master/projects/libyang) | [OOB read](https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=71619) | Vertex AI | [Default](prompts/template_xml) | All |
| [`openbabel`](https://github.com/google/oss-fuzz/tree/master/projects/openbabel) | [OOB read](https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=71650) | Vertex AI | [Default](prompts/template_xml) | All |
| [`exiv2`](https://github.com/google/oss-fuzz/tree/master/projects/exiv2) | [OOB read](https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=71759) | Vertex AI | [Default](prompts/template_xml) | All |
| Undisclosed | Java RCE (pending maintainer triage) | Vertex AI |  [Default](prompts/template_xml) | Far reach, low coverage |
| Undisclosed | Regexp DoS (pending maintainer triage) | Vertex AI |  [Default](prompts/template_xml) | Far reach, low coverage |
| Undisclosed | [OOB read](https://issues.oss-fuzz.com/issues/370872803) | Vertex AI | [Default](prompts/template_xml) | All |
| Undisclosed | [OOB write](https://issues.oss-fuzz.com/issues/378009361) | Vertex AI | [Default](prompts/template_xml) | All |
| Undisclosed | [OOB read](https://issues.oss-fuzz.com/issues/391234167) | Vertex AI | [Default](prompts/template_xml) | All |
| Undisclosed | [OOB read](https://issues.oss-fuzz.com/issues/391453674) | Vertex AI | [Default](prompts/template_xml) | All |
| Undisclosed | [Use after free](https://issues.oss-fuzz.com/issues/391456091) | Vertex AI | Agent prompt | All |

These bugs could only have been discovered with newly generated targets. They were not reachable with existing OSS-Fuzz targets.

## Current top coverage improvements by project

| Project | Total coverage gain	| Total relative gain	| OSS-Fuzz-gen total covered lines | OSS-Fuzz-gen new covered lines | Existing covered lines | Total project lines |
| --------| ------------------- | ------------------- | -------------------------------- | ------------------------------ | ---------------------- | ------------------- |
| phmap | 98.42% | 205.75% | 1601 | 1181 | 574 | 1120 |
| usbguard | 97.62% | 26.04% | 24550 | 5463 | 20979 | 3564 |
| onednn | 96.67% | 7057.14% | 5434 | 5434 | 77 | 210 |
| avahi | 82.06% | 155.90% | 3358 | 2814 | 1805 | 3046 |
| pugixml | 72.98% | 194.95% | 9015 | 6646 | 3409 | 7662 |
| librdkafka | 66.88% | 845.57% | 5019 | 4490 | 531 | 1169 |
| casync | 66.75% | 903.23% | 1171 | 1120 | 124 | 1678 |
| tomlplusplus | 61.06% | 331.10% | 4755 | 3652 | 1103 | 5981 |
| astc-encoder | 59.35% | 177.88% | 2726 | 1745 | 981 | 2940 |
| mruby | 48.56% | 0.00% | 34493 | 34493 | 0 | 71038 |
| arduinojson | 42.10% | 85.80% | 3344 | 1800 | 2098 | 4276 |
| json | 41.13% | 66.51% | 5051 | 3339 | 5020 | 8119 |
| double-conversion | 40.40% | 88.12% | 1663 | 779 | 884 | 1928 |
| tinyobjloader | 38.26% | 77.01% | 1157 | 717 | 931 | 1874 |
| glog | 38.18% | 58.69% | 895 | 331 | 564 | 867 |
| cppitertools | 35.78% | 45.07% | 253 | 151 | 335 | 422 |
| eigen | 35.38% | 190.70% | 2643 | 1947 | 1021 | 5503 |
| glaze | 34.55% | 30.06% | 2920 | 2416 | 8036 | 6993 |
| rapidjson | 31.83% | 148.07% | 1585 | 958 | 647 | 3010 |
| libunwind | 30.58% | 83.25% | 2899 | 1342 | 1612 | 4388 |
| openh264 | 30.07% | 50.14% | 6607 | 5751 | 11470 | 19123 |

\* "Total project lines" measures the source code of the project-under-test compiled and linked by the preexisting human-written fuzz targets from OSS-Fuzz. 

\* "Total coverage gain" is calculated using a denominator of the "Total project lines". "Total relative gain" is the increase in coverage compared to the old number of covered lines.

\* Additional code from the project-under-test maybe included when compiling the new fuzz targets and result in high percentage gains.

## Citing This Work
Please click on the _'Cite this repository'_ button located on the right-hand side of this GitHub page for citation details.
