// Copyright 2023 The Pigweed Authors
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

#include <fuzzer/FuzzedDataProvider.h>

#include "pw_bluetooth_sapphire/internal/host/common/advertising_data.h"
#include "pw_bluetooth_sapphire/internal/host/common/byte_buffer.h"

namespace bt::common {

void fuzz(const uint8_t *data, size_t size) {
  FuzzedDataProvider fuzzed_data(data, size);
  auto adv_flags = fuzzed_data.ConsumeIntegral<AdvFlags>();
  bool include_adv_flags = fuzzed_data.ConsumeBool();
  auto write_buffer_size = fuzzed_data.ConsumeIntegralInRange(0, 2000);
  auto adv_data = fuzzed_data.ConsumeRemainingBytes<uint8_t>();

  AdvertisingData::ParseResult result = AdvertisingData::FromBytes(BufferView(adv_data));

  if (result.is_ok()) {
    DynamicByteBuffer write_buffer(write_buffer_size);
    result->WriteBlock(&write_buffer, include_adv_flags ? std::optional(adv_flags) : std::nullopt);
  }
}

} // namespace bt::common

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  bt::common::fuzz(data, size);
  return 0;
}
