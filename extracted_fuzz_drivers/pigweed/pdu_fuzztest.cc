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

#include "pw_bluetooth_sapphire/internal/host/sdp/pdu.h"

namespace bt::sdp {

void fuzz(const uint8_t *data, size_t size) {
  FuzzedDataProvider fuzzed_data(data, size);
  uint8_t type = fuzzed_data.ConsumeIntegral<uint8_t>();
  std::vector<uint8_t> remaining_bytes = fuzzed_data.ConsumeRemainingBytes<uint8_t>();
  DynamicByteBuffer buf(remaining_bytes.size());
  memcpy(buf.mutable_data(), remaining_bytes.data(), remaining_bytes.size());
  fit::result<Error<>> status = fit::ok();
  ErrorResponse error_response;
  ServiceSearchResponse service_search_response;
  ServiceAttributeResponse service_attribute_response;
  ServiceSearchAttributeResponse service_search_attribute_response;
  switch (type % 4) {
  case 0:
    status = error_response.Parse(buf);
    break;
  case 1:
    status = service_search_response.Parse(buf);
    break;
  case 2:
    status = service_attribute_response.Parse(buf);
    break;
  case 3:
    status = service_search_attribute_response.Parse(buf);
    break;
  }
}

} // namespace bt::sdp

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  bt::sdp::fuzz(data, size);
  return 0;
}
