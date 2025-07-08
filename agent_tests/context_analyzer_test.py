# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""A test for the function analyzer agent."""

import argparse
import json
from data_prep import introspector
import logger
import os
from typing import List

from results import AnalysisResult, CrashResult, RunResult
import run_all_experiments
from agent import context_analyzer
from experiment import benchmark as benchmarklib
from experiment import workdir
from llm_toolkit import models
from datetime import datetime
import traceback

import run_one_experiment

RESULTS_DIR = f'./results-{datetime.now().strftime("%Y-%m-%d-%H-%M")}'

NUM_ANA = int(os.getenv('LLM_NUM_ANA', '2'))


def parse_args() -> argparse.Namespace:
  """Parses command line arguments."""
  parser = argparse.ArgumentParser(
      description='Evaluate the function analyzer agent.')

  parser.add_argument('-y',
                      '--benchmark-yaml',
                      type=str,
                      help='A benchmark YAML file.')

  parser.add_argument('-b',
                      '--benchmarks-directory',
                      type=str,
                      help='A directory containing benchmark YAML files.')

  parser.add_argument(
      '-g',
      '--generate-benchmarks',
      help=('Generate benchmarks and use those for analysis. This is a string '
            'of comma-separated heuristics to use when identifying benchmark '
            'targets.'),
      type=str)

  parser.add_argument('-mr',
                      '--max-round',
                      type=int,
                      default=100,
                      help='Max trial round for agents.')

  parser.add_argument('-e',
                      '--introspector-endpoint',
                      type=str,
                      default=introspector.DEFAULT_INTROSPECTOR_ENDPOINT)


  parser.add_argument(
      '-of',
      '--oss-fuzz-dir',
      help='OSS-Fuzz dir path to use. Create temporary directory by default.',
      default='')

  parser.add_argument('-w', '--work-dir', default=RESULTS_DIR)

  parsed_args = parser.parse_args()

  return parsed_args

def get_mock_last_result(args, benchmark: benchmarklib.Benchmark) -> AnalysisResult:

  stacktrace = """
AddressSanitizer: SEGV on unknown address 0x000000000000 (pc 0x557d26695151 bp 0x7ffe468518b0 sp 0x7ffe46851860 T0)
==17==The signal is caused by a READ memory access.
==17==Hint: address points to the zero page.
SCARINESS: 10 (null-deref)
#0 0x557d26695151 in toc_header /src/hoextdown/src/html.c:987
#1 0x557d266770a0 in parse_atxheader /src/hoextdown/src/document.c:2740:3
#2 0x557d266770a0 in parse_block /src/hoextdown/src/document.c:3558:11
#3 0x557d26675c36 in hoedown_document_render /src/hoextdown/src/document.c:4162:3
#4 0x557d2666e8ef in LLVMFuzzerTestOneInput /src/hoextdown/test/hoedown_fuzzer.c:78:3
#5 0x557d26523300 in fuzzer::Fuzzer::ExecuteCallback(unsigned char const*, unsigned long) /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp:614:13
#6 0x557d26522b25 in fuzzer::Fuzzer::RunOne(unsigned char const*, unsigned long, bool, fuzzer::InputInfo*, bool, bool*) /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp:516:7
#7 0x557d26524305 in fuzzer::Fuzzer::MutateAndTestOne() /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp:760:19
#8 0x557d26525095 in fuzzer::Fuzzer::Loop(std::__Fuzzer::vector<fuzzer::SizedFile, std::__Fuzzer::allocator<fuzzer::SizedFile>>&) /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp:905:5
#9 0x557d26513edb in fuzzer::FuzzerDriver(int*, char***, int (*)(unsigned char const*, unsigned long)) /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerDriver.cpp:914:6
#10 0x557d2653f2b2 in main /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerMain.cpp:20:10
#11 0x7f964403b082 in __libc_start_main (/lib/x86_64-linux-gnu/libc.so.6+0x24082) (BuildId: 5792732f783158c66fb4f3756458ca24e46e827d)
#12 0x557d2650675d in _start (out/libfuzzer-address-x86_64/hoedown_fuzzer+0x5575d)

DEDUP_TOKEN: toc_header--parse_atxheader--parse_block
AddressSanitizer can not provide additional info.
  """

  insight = """
The crash is caused by a null pointer dereference in the `toc_header` function in `/src/hoextdown/src/html.c`.

Specifically, at line 987:
`rndr_header_id(ob, content->data, content->size, 1, data);`

The `content` pointer is dereferenced without a prior null check. A null check for `content` exists at line 991, but this is after the pointer has already been dereferenced at line 987, which is the source of the bug.

The fix is to move the null check for `content` to before the dereference. The `if (content)` block starting at line 991 should be moved to enclose the code that uses `content`, including the call to `rndr_header_id` at line 987.

```c
// src/html.c:985
} else {
if (content) { // Add this check
hoedown_buffer_puts(ob, "<a href=\"#");
rndr_header_id(ob, content->data, content->size, 1, data);
hoedown_buffer_puts(ob, "\">");
}
}

if (content) {
hoedown_buffer_put(ob, content->data, content->size);
}
HOEDOWN_BUFPUTSL(ob, "</a>\n");
```

The corrected logic should look something like this:

```c
// Potential patch
} else {
if (content) {
hoedown_buffer_puts(ob, "<a href=\"#");
rndr_header_id(ob, content->data, content->size, 1, data);
hoedown_buffer_puts(ob, "\">");
}
}

if (content) {
hoedown_buffer_put(ob, content->data, content->size);
}
if (content) { // This check should wrap the closing tag as well
HOEDOWN_BUFPUTSL(ob, "</a>\n");
}
```
A more robust fix would be to ensure that if `content` is NULL, the `<a>` tag is not opened at all.

The bug is in the project code, not the fuzzer driver. The fuzzer correctly identified a valid crash.
  """


  fuzz_target_source = """
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "context_test.h"
#include "/src/hoextdown/src/document.h"
#include "html.h"

#define DEF_OUNIT 64
#define DEF_MAX_NESTING 16

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
// Need at least 8 bytes for config:
// 4: extensions, 1: attr_activation, 2: html_flags, 1: nesting_level/renderer_choice
if (size < 8) {
return 0;
}

/* Use the first bytes of input to control flags and options */
hoedown_extensions extensions = *(const uint32_t*)data;
data += 4;
size -= 4;

uint8_t attr_activation = data[0];
data += 1;
size -= 1;

// Use 2 bytes for HTML flags to cover all enum values.
hoedown_html_flags html_flags = *(const uint16_t*)data;
data += 2;
size -= 2;

// Use 1 byte to control nesting level and renderer choice.
uint8_t fuzzer_choice = data[0];
data += 1;
size -= 1;

int nesting_level = fuzzer_choice % 16; // Limit nesting level
int renderer_type = fuzzer_choice / 16; // Use upper bits to choose renderer

hoedown_renderer *renderer = NULL;
void (*renderer_free)(hoedown_renderer *);

/* Let the fuzzer choose between the standard and TOC renderer */
if (renderer_type % 2 == 0) {
renderer = hoedown_html_renderer_new(html_flags, nesting_level);
} else {
renderer = hoedown_html_toc_renderer_new(nesting_level);
}
renderer_free = hoedown_html_renderer_free;

if (!renderer) {
return 0;
}

/* Perform Markdown rendering */
hoedown_buffer *ob = hoedown_buffer_new(DEF_OUNIT);
hoedown_buffer *meta = hoedown_buffer_new(DEF_OUNIT);
hoedown_document *document = hoedown_document_new(
renderer, extensions, DEF_MAX_NESTING, attr_activation, NULL, meta);

if (!document) {
renderer_free(renderer);
hoedown_buffer_free(ob);
hoedown_buffer_free(meta);
return 0;
}

/*
* Call hoedown_document_render instead of hoedown_document_render_inline.
* This function processes the input as a full Markdown document, including
* block-level elements like tables, lists, headers, and code blocks, which
* will significantly increase coverage.
*/
hoedown_document_render(document, ob, data, size);

/* Cleanup */
hoedown_document_free(document);
renderer_free(renderer);
hoedown_buffer_free(ob);
hoedown_buffer_free(meta);

return 0;
}
  """

  run_result = RunResult(
      benchmark=benchmark,
      trial=1,
      work_dirs=args.work_dirs,
      author=None,
      chat_history={},
      crashes=True,
      fuzz_target_source=fuzz_target_source
  )


  crash_result = CrashResult(benchmark=benchmark,
                               trial=1,
                               work_dirs=args.work_dirs,
                               author=None,
                               chat_history={},
                               stacktrace=stacktrace,
                               true_bug=True,
                               insight=insight,)

  analysis_result = AnalysisResult(
      author=None,
      run_result=run_result,
      crash_result=crash_result,
      chat_history={})

  return analysis_result


if __name__ == '__main__':

  model = models.LLM.setup(ai_binary='', name='vertex_ai_gemini-2-5-pro-chat')

  args = parse_args()

  args.benchmark_yaml = './benchmark-sets/comparison/hoextdown.yaml'

  # Initialize the working directory
  args.work_dirs = workdir.WorkDirs(args.work_dir)

  introspector.set_introspector_endpoints(args.introspector_endpoint)

  run_one_experiment.prepare(args.oss_fuzz_dir)

  # Initialize benchmarks
  benchmarks: List[
      benchmarklib.Benchmark] = run_all_experiments.prepare_experiment_targets(
          args)

  if len(benchmarks) == 0:
    raise ValueError('No benchmarks found in the YAML file.')

  logger.info('Loaded %d benchmarks from the YAML file %s.', len(benchmarks),
              args.benchmark_yaml, trial=1)

  benchmark = benchmarks[0]  # For testing, we only analyze the first benchmark

  analyzer = context_analyzer.ContextAnalyzer(trial=1,
                                                llm=model,
                                                args=args,
                                                benchmark=benchmark)

  last_result = get_mock_last_result(args, benchmark)

  # Run the context analyzer
  try:
    result = analyzer.execute([last_result])

    # Write result to new file in work directory
    result_file = os.path.join(args.work_dirs.base,
                               f'{benchmark.function_name}_context_analysis_result.json')
    with open(result_file, 'w') as file:
      json.dump(result.to_dict(), file, indent=2)
  except Exception as e:
    logger.error('Error during analysis for benchmark %s: %s\n%s',
           benchmark.function_name, e, traceback.format_exc(), trial=1)

