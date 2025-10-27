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

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <vector>

#include "fuzz.h"
#include "pw_fuzzer/fuzzed_data_provider.h"
#include "pw_protobuf/stream_decoder.h"
#include "pw_span/span.h"
#include "pw_status/status.h"
#include "pw_status/status_with_size.h"
#include "pw_stream/memory_stream.h"
#include "pw_stream/stream.h"

namespace pw::protobuf::fuzz {
namespace {

void RecursiveFuzzedDecode(FuzzedDataProvider &provider, StreamDecoder &decoder, uint32_t depth = 0) {
  constexpr size_t kMaxRepeatedRead = 256;
  constexpr size_t kMaxDepth = 3;

  if (depth > kMaxDepth) {
    return;
  }
  while (provider.remaining_bytes() != 0 && decoder.Next().ok()) {
    FieldType field_type = provider.ConsumeEnum<FieldType>();
    switch (field_type) {
    case kUint32:
      if (!decoder.ReadUint32().status().ok()) {
        return;
      }
      break;
    case kPackedUint32: {
      uint32_t packed[kMaxRepeatedRead] = {0};
      if (!decoder.ReadPackedUint32(packed).status().ok()) {
        return;
      }
    } break;
    case kUint64:
      if (!decoder.ReadUint64().status().ok()) {
        return;
      }
      break;
    case kPackedUint64: {
      uint64_t packed[kMaxRepeatedRead] = {0};
      if (!decoder.ReadPackedUint64(packed).status().ok()) {
        return;
      }
    } break;
    case kInt32:
      if (!decoder.ReadInt32().status().ok()) {
        return;
      }
      break;
    case kPackedInt32: {
      int32_t packed[kMaxRepeatedRead] = {0};
      if (!decoder.ReadPackedInt32(packed).status().ok()) {
        return;
      }
    } break;
    case kInt64:
      if (!decoder.ReadInt64().status().ok()) {
        return;
      }
      break;
    case kPackedInt64: {
      int64_t packed[kMaxRepeatedRead] = {0};
      if (!decoder.ReadPackedInt64(packed).status().ok()) {
        return;
      }
    } break;
    case kSint32:
      if (!decoder.ReadSint32().status().ok()) {
        return;
      }
      break;
    case kPackedSint32: {
      int32_t packed[kMaxRepeatedRead] = {0};
      if (!decoder.ReadPackedSint32(packed).status().ok()) {
        return;
      }
    } break;
    case kSint64:
      if (!decoder.ReadSint64().status().ok()) {
        return;
      }
      break;
    case kPackedSint64: {
      int64_t packed[kMaxRepeatedRead] = {0};
      if (!decoder.ReadPackedSint64(packed).status().ok()) {
        return;
      }
    } break;
    case kBool:
      if (!decoder.ReadBool().status().ok()) {
        return;
      }
      break;
    case kFixed32:
      if (!decoder.ReadFixed32().status().ok()) {
        return;
      }
      break;
    case kPackedFixed32: {
      uint32_t packed[kMaxRepeatedRead] = {0};
      if (!decoder.ReadPackedFixed32(packed).status().ok()) {
        return;
      }
    } break;
    case kFixed64:
      if (!decoder.ReadFixed64().status().ok()) {
        return;
      }
      break;
    case kPackedFixed64: {
      uint64_t packed[kMaxRepeatedRead] = {0};
      if (!decoder.ReadPackedFixed64(packed).status().ok()) {
        return;
      }
    } break;
    case kSfixed32:
      if (!decoder.ReadSfixed32().status().ok()) {
        return;
      }
      break;
    case kPackedSfixed32: {
      int32_t packed[kMaxRepeatedRead] = {0};
      if (!decoder.ReadPackedSfixed32(packed).status().ok()) {
        return;
      }
    } break;
    case kSfixed64:
      if (!decoder.ReadSfixed64().status().ok()) {
        return;
      }
      break;
    case kPackedSfixed64: {
      int64_t packed[kMaxRepeatedRead] = {0};
      if (!decoder.ReadPackedSfixed64(packed).status().ok()) {
        return;
      }
    } break;
    case kFloat:
      if (!decoder.ReadFloat().status().ok()) {
        return;
      }
      break;
    case kPackedFloat: {
      float packed[kMaxRepeatedRead] = {0};
      if (!decoder.ReadPackedFloat(packed).status().ok()) {
        return;
      }
    } break;
    case kDouble:
      if (!decoder.ReadDouble().status().ok()) {
        return;
      }
      break;
    case kPackedDouble: {
      double packed[kMaxRepeatedRead] = {0};
      if (!decoder.ReadPackedDouble(packed).status().ok()) {
        return;
      }
    } break;
    case kBytes: {
      std::byte bytes[kMaxRepeatedRead] = {std::byte{0}};
      if (!decoder.ReadBytes(bytes).status().ok()) {
        return;
      }
    } break;
    case kString: {
      char str[kMaxRepeatedRead] = {0};
      if (!decoder.ReadString(str).status().ok()) {
        return;
      }
    } break;
    case kPush: {
      StreamDecoder nested_decoder = decoder.GetNestedDecoder();
      RecursiveFuzzedDecode(provider, nested_decoder, depth + 1);
    } break;
    case kPop:
      if (depth > 0) {
        // Special "field". The marks the end of a nested message.
        return;
      }
    }
  }
}

void TestOneInput(FuzzedDataProvider &provider) {
  constexpr size_t kMaxFuzzedProtoSize = 4096;
  std::vector<std::byte> proto_message_data = provider.ConsumeBytes<std::byte>(provider.ConsumeIntegralInRange<size_t>(0, kMaxFuzzedProtoSize));
  stream::MemoryReader memory_reader(proto_message_data);
  StreamDecoder decoder(memory_reader);
  RecursiveFuzzedDecode(provider, decoder);
}

} // namespace
} // namespace pw::protobuf::fuzz

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider provider(data, size);
  pw::protobuf::fuzz::TestOneInput(provider);
  return 0;
}
