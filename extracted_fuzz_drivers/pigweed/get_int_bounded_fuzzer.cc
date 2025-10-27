// Copyright 2022 The Pigweed Authors
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

#include <cstddef>
#include <cstdint>
#include <limits>

#include "pw_assert/check.h"
#include "pw_fuzzer/fuzzed_data_provider.h"
#include "pw_random/fuzzer.h"

namespace {
enum class IntegerType : uint8_t {
  kUint8,
  kUint16,
  kUint32,
  kUint64,
  kMaxValue = kUint64,
};

template <typename T> void FuzzGetInt(FuzzedDataProvider *provider) {
  pw::random::FuzzerRandomGenerator rng(provider);
  T value = 0;
  T bound = provider->ConsumeIntegralInRange<T>(1, std::numeric_limits<T>::max());
  rng.GetInt(value, bound);
  PW_CHECK(value < bound);
}
} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider provider(data, size);
  switch (provider.ConsumeEnum<IntegerType>()) {
  case IntegerType::kUint8:
    FuzzGetInt<uint8_t>(&provider);
    break;
  case IntegerType::kUint16:
    FuzzGetInt<uint16_t>(&provider);
    break;
  case IntegerType::kUint32:
    FuzzGetInt<uint32_t>(&provider);
    break;
  case IntegerType::kUint64:
    FuzzGetInt<uint64_t>(&provider);
    break;
  }
  return 0;
}
