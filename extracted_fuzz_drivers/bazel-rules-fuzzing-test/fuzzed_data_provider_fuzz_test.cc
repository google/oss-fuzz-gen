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

// A fuzz target that demonstrates the use of FuzzeddataProvider.

#include <cstddef>
#include <cstdint>

// Workaround for
// https://github.com/llvm/llvm-project/commit/0cccccf0d2cbd707503263785f9a0407d3e2bd5ea
// causing missing symbol errors in the FuzzedDataProvider.h header with
// clang 10.
// FIXME: Remove once a clang release ships with this commit.
#include <fuzzer/FuzzedDataProvider.h> // NOLINT
#include <limits>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider fuzzed_data(data, size);

  const auto first_part_size = fuzzed_data.ConsumeIntegral<uint16_t>();
  std::vector<uint8_t> first_part = fuzzed_data.ConsumeBytes<uint8_t>(first_part_size);
  std::vector<uint8_t> second_part = fuzzed_data.ConsumeRemainingBytes<uint8_t>();

  return 0;
}
