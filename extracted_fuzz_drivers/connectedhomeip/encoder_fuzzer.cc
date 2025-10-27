// Copyright 2019 The Pigweed Authors
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
#include <cstring>
#include <vector>

#include "fuzz.h"
#include "pw_fuzzer/asan_interface.h"
#include "pw_fuzzer/fuzzed_data_provider.h"
#include "pw_protobuf/encoder.h"
#include "pw_span/span.h"

namespace pw::protobuf::fuzz {
namespace {

// TODO: b/235289495 - Move this to pw_fuzzer/fuzzed_data_provider.h

// Uses the given |provider| to pick and return a number between 0 and the
// maximum numbers of T that can be generated from the remaining input data.
template <typename T> size_t ConsumeSize(FuzzedDataProvider &provider) {
  size_t max = provider.remaining_bytes() / sizeof(T);
  return provider.ConsumeIntegralInRange<size_t>(0, max);
}

// Uses the given |provider| to generate several instances of T, store them in
// |data|, and then return a span to them. It is the caller's responsbility
// to ensure |data| remains in scope as long as the returned span.
template <typename T> span<const T> ConsumeSpan(FuzzedDataProvider &provider, std::vector<T> *data) {
  size_t num = ConsumeSize<T>(provider);
  size_t off = data->size();
  if (num == 0) {
    return span<const T>();
  }

  data->reserve(off + num);
  for (size_t i = 0; i < num; ++i) {
    if constexpr (std::is_floating_point<T>::value) {
      data->push_back(provider.ConsumeFloatingPoint<T>());
    } else {
      data->push_back(provider.ConsumeIntegral<T>());
    }
  }
  return span(&((*data)[off]), num);
}

// Uses the given |provider| to generate a string, store it in |data|, and
// return a C-style representation. It is the caller's responsbility to
// ensure |data| remains in scope as long as the returned char*.
const char *ConsumeString(FuzzedDataProvider &provider, std::vector<std::string> *data) {
  size_t off = data->size();
  // OSS-Fuzz's clang doesn't have the zero-parameter version of
  // ConsumeRandomLengthString yet.
  size_t max_length = std::numeric_limits<size_t>::max();
  data->push_back(provider.ConsumeRandomLengthString(max_length));
  return (*data)[off].c_str();
}

// Uses the given |provider| to generate non-arithmetic bytes, store them in
// |data|, and return a span to them. It is the caller's responsbility to
// ensure |data| remains in scope as long as the returned span.
span<const std::byte> ConsumeBytes(FuzzedDataProvider &provider, std::vector<std::byte> *data) {
  size_t num = ConsumeSize<std::byte>(provider);
  auto added = provider.ConsumeBytes<std::byte>(num);
  size_t off = data->size();
  num = added.size();
  data->insert(data->end(), added.begin(), added.end());
  // It's possible nothing was added, and the vector was empty to begin with.
  if (data->empty()) {
    return span<const std::byte>();
  }
  return span(&((*data)[off]), num);
}

void RecursiveFuzzedEncode(FuzzedDataProvider &provider, StreamEncoder &encoder, uint32_t depth = 0) {
  constexpr size_t kMaxDepth = 256;
  if (depth > kMaxDepth) {
    return;
  }

  // Storage for generated spans
  std::vector<uint32_t> u32s;
  std::vector<uint64_t> u64s;
  std::vector<int32_t> s32s;
  std::vector<int64_t> s64s;
  std::vector<float> floats;
  std::vector<double> doubles;
  std::vector<std::string> strings;
  std::vector<std::byte> bytes;

  // Consume the fuzzing input, using it to generate a sequence of fields to
  // encode. Both the uint32_t field IDs and the fields values are generated.
  // Don't try to detect errors, ensures pushes and pops are balanced, or
  // otherwise hold the interface correctly. Instead, fuzz the widest possbile
  // set of inputs to the encoder to ensure it doesn't misbehave.
  while (provider.remaining_bytes() != 0) {
    switch (provider.ConsumeEnum<FieldType>()) {
    case kUint32:
      encoder.WriteUint32(provider.ConsumeIntegral<uint32_t>(), provider.ConsumeIntegral<uint32_t>()).IgnoreError();
      break;
    case kPackedUint32:
      encoder.WritePackedUint32(provider.ConsumeIntegral<uint32_t>(), ConsumeSpan<uint32_t>(provider, &u32s)).IgnoreError();
      break;
    case kUint64:
      encoder.WriteUint64(provider.ConsumeIntegral<uint32_t>(), provider.ConsumeIntegral<uint64_t>()).IgnoreError();
      break;
    case kPackedUint64:
      encoder.WritePackedUint64(provider.ConsumeIntegral<uint32_t>(), ConsumeSpan<uint64_t>(provider, &u64s)).IgnoreError();
      break;
    case kInt32:
      encoder.WriteInt32(provider.ConsumeIntegral<uint32_t>(), provider.ConsumeIntegral<int32_t>()).IgnoreError();
      break;
    case kPackedInt32:
      encoder.WritePackedInt32(provider.ConsumeIntegral<uint32_t>(), ConsumeSpan<int32_t>(provider, &s32s)).IgnoreError();
      break;
    case kInt64:
      encoder.WriteInt64(provider.ConsumeIntegral<uint32_t>(), provider.ConsumeIntegral<int64_t>()).IgnoreError();
      break;
    case kPackedInt64:
      encoder.WritePackedInt64(provider.ConsumeIntegral<uint32_t>(), ConsumeSpan<int64_t>(provider, &s64s)).IgnoreError();
      break;
    case kSint32:
      encoder.WriteSint32(provider.ConsumeIntegral<uint32_t>(), provider.ConsumeIntegral<int32_t>()).IgnoreError();
      break;
    case kPackedSint32:
      encoder.WritePackedSint32(provider.ConsumeIntegral<uint32_t>(), ConsumeSpan<int32_t>(provider, &s32s)).IgnoreError();
      break;
    case kSint64:
      encoder.WriteSint64(provider.ConsumeIntegral<uint32_t>(), provider.ConsumeIntegral<int64_t>()).IgnoreError();
      break;
    case kPackedSint64:
      encoder.WritePackedSint64(provider.ConsumeIntegral<uint32_t>(), ConsumeSpan<int64_t>(provider, &s64s)).IgnoreError();
      break;
    case kBool:
      encoder.WriteBool(provider.ConsumeIntegral<uint32_t>(), provider.ConsumeBool()).IgnoreError();
      break;
    case kFixed32:
      encoder.WriteFixed32(provider.ConsumeIntegral<uint32_t>(), provider.ConsumeIntegral<uint32_t>()).IgnoreError();
      break;
    case kPackedFixed32:
      encoder.WritePackedFixed32(provider.ConsumeIntegral<uint32_t>(), ConsumeSpan<uint32_t>(provider, &u32s)).IgnoreError();
      break;
    case kFixed64:
      encoder.WriteFixed64(provider.ConsumeIntegral<uint32_t>(), provider.ConsumeIntegral<uint64_t>()).IgnoreError();
      break;
    case kPackedFixed64:
      encoder.WritePackedFixed64(provider.ConsumeIntegral<uint32_t>(), ConsumeSpan<uint64_t>(provider, &u64s)).IgnoreError();
      break;
    case kSfixed32:
      encoder.WriteSfixed32(provider.ConsumeIntegral<uint32_t>(), provider.ConsumeIntegral<int32_t>()).IgnoreError();
      break;
    case kPackedSfixed32:
      encoder.WritePackedSfixed32(provider.ConsumeIntegral<uint32_t>(), ConsumeSpan<int32_t>(provider, &s32s)).IgnoreError();
      break;
    case kSfixed64:
      encoder.WriteSfixed64(provider.ConsumeIntegral<uint32_t>(), provider.ConsumeIntegral<int64_t>()).IgnoreError();
      break;
    case kPackedSfixed64:
      encoder.WritePackedSfixed64(provider.ConsumeIntegral<uint32_t>(), ConsumeSpan<int64_t>(provider, &s64s)).IgnoreError();
      break;
    case kFloat:
      encoder.WriteFloat(provider.ConsumeIntegral<uint32_t>(), provider.ConsumeFloatingPoint<float>()).IgnoreError();
      break;
    case kPackedFloat:
      encoder.WritePackedFloat(provider.ConsumeIntegral<uint32_t>(), ConsumeSpan<float>(provider, &floats)).IgnoreError();
      break;
    case kDouble:
      encoder.WriteDouble(provider.ConsumeIntegral<uint32_t>(), provider.ConsumeFloatingPoint<double>()).IgnoreError();
      break;
    case kPackedDouble:
      encoder.WritePackedDouble(provider.ConsumeIntegral<uint32_t>(), ConsumeSpan<double>(provider, &doubles)).IgnoreError();
      break;
    case kBytes:
      encoder.WriteBytes(provider.ConsumeIntegral<uint32_t>(), ConsumeBytes(provider, &bytes)).IgnoreError();
      break;
    case kString:
      encoder.WriteString(provider.ConsumeIntegral<uint32_t>(), ConsumeString(provider, &strings)).IgnoreError();
      break;
    case kPush: {
      // Special "field". The marks the start of a nested message.
      StreamEncoder nested_encoder = encoder.GetNestedEncoder(provider.ConsumeIntegral<uint32_t>());
      RecursiveFuzzedEncode(provider, nested_encoder, depth + 1);
      break;
    }
    case kPop:
      if (depth > 0) {
        // Special "field". The marks the end of a nested message.
        return;
      }
    }
  }
}

void TestOneInput(FuzzedDataProvider &provider) {
  static std::byte buffer[65536];

  // Pick a subset of the buffer that the fuzzer is allowed to use, and poison
  // the rest.
  size_t unpoisoned_length = provider.ConsumeIntegralInRange<size_t>(0, sizeof(buffer));
  ByteSpan unpoisoned(buffer, unpoisoned_length);
  void *poisoned = &buffer[unpoisoned_length];
  size_t poisoned_length = sizeof(buffer) - unpoisoned_length;
  ASAN_POISON_MEMORY_REGION(poisoned, poisoned_length);

  pw::protobuf::MemoryEncoder encoder(unpoisoned);
  RecursiveFuzzedEncode(provider, encoder);

  // Don't forget to unpoison for the next iteration!
  ASAN_UNPOISON_MEMORY_REGION(poisoned, poisoned_length);
}

} // namespace
} // namespace pw::protobuf::fuzz

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider provider(data, size);
  pw::protobuf::fuzz::TestOneInput(provider);
  return 0;
}
