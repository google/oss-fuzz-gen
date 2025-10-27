// Copyright 2020 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// This is a very basic fuzz test for RE2, for illustrative purposes.
// See RE2's own fuzz tests for real-world examples that follow best practices,
// e.g.: https://github.com/google/re2/blob/master/re2/fuzzing/re2_fuzzer.cc

#include <cstddef>
#include <cstdint>
#include <string>

#include "re2/re2.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  RE2 re(std::string(reinterpret_cast<const char *>(data), size), RE2::Quiet);
  return 0;
}
