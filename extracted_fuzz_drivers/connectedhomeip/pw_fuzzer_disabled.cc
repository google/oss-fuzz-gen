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

// When fuzzing is disabled, this test is compiled in place of the fuzzer
// binary. It verifies the fuzzer can be built and linked, and that it will not
// crash on known, fixed inputs.

#include <cstddef>
#include <cstdint>

#include "pw_log/log.h"
#include "pw_unit_test/framework.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

TEST(Fuzzer, EmptyInput) {
  PW_LOG_INFO("Fuzzing is disabled for the current platform and/or compiler.");
  PW_LOG_INFO("Executing the fuzz target function as a unit test instead.");
  uint8_t tmp = 0;
  EXPECT_EQ(LLVMFuzzerTestOneInput(&tmp, 0), 0);
  EXPECT_EQ(LLVMFuzzerTestOneInput(nullptr, 0), 0);
}

// TODO: b/234883542 - Add support for testing a seed corpus.
