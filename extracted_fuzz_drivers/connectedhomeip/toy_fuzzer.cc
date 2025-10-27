// Copyright 2020 The Pigweed Authors
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may not
// use this file except in compliance with the License. You may obtain a copy of
// the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
// License for the specific language governing permissions and limitations under
// the License.

// This is a simple example of how to write a fuzzer. The target function is
// crafted to demonstrates how the fuzzer can analyze conditional branches and
// incrementally cover more and more code until a defect is found.
//
// See build_and_run_toy_fuzzer.sh for examples of how you can build and run
// this example.

#include <cstddef>
#include <cstdint>
#include <string_view>

#include "pw_fuzzer/fuzzed_data_provider.h"
#include "pw_status/status.h"

namespace pw::fuzzer::example {
namespace {

// The code to fuzz. This would normally be in separate library.
Status SomeAPI(std::string_view s1, std::string_view s2) {
  if (s1 == "hello") {
    if (s2 == "world") {
      abort();
    }
  }
  return OkStatus();
}

} // namespace
} // namespace pw::fuzzer::example

// The fuzz target function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider provider(data, size);
  std::string s1 = provider.ConsumeRandomLengthString();
  std::string s2 = provider.ConsumeRemainingBytesAsString();
  pw::fuzzer::example::SomeAPI(s1, s2).IgnoreError();
  return 0;
}
