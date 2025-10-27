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

#include "pw_bluetooth_sapphire/internal/host/l2cap/command_handler.h"

namespace bt::l2cap::internal {
class TestResponse : public CommandHandler::Response {
public:
  TestResponse(SignalingChannel::Status status) : CommandHandler::Response(status) {}

  bool TestParseReject(const ByteBuffer &rej_payload_buf) { return ParseReject(rej_payload_buf); }
};

void fuzz(const uint8_t *data, size_t size) {
  DynamicByteBuffer buf(size);
  memcpy(buf.mutable_data(), data, size);
  TestResponse test_response(SignalingChannel::Status::kSuccess);
  bool result = test_response.TestParseReject(buf);
  (void)result;
}

} // namespace bt::l2cap::internal

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  bt::l2cap::internal::fuzz(data, size);
  return 0;
}
