/*
 * Copyright 2021 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <cassert>
#include <cstdint>
#include <cstdio>
#include <memory>
#include <string>

#include "lldb-eval/api.h"
#include "lldb/API/SBError.h"
#include "tools/fuzzer/libfuzzer_common.h"

// Global variables that are initialized in `LLVMFuzzerInitialize`.
static fuzzer::LibfuzzerState g_state;

extern "C" size_t LLVMFuzzerCustomMutator(uint8_t *data, size_t size, size_t max_size, unsigned int seed) { return g_state.custom_mutate(data, size, max_size, seed); }

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  std::string expr = g_state.input_to_expr(data, size);
  lldb::SBError error;
  lldb_eval::EvaluateExpression(g_state.frame(), expr.c_str(), error);
  return 0;
}

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv) { return g_state.init(argc, argv); }
