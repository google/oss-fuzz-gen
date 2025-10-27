// Copyright 2019 The Chromium Authors. All rights reserved.

#include "third_party/icu/fuzzers/fuzzer_utils.h"
#include "third_party/icu/source/common/unicode/appendable.h"
#include <fuzzer/FuzzedDataProvider.h>
#include <stddef.h>
#include <stdint.h>
#include <vector>

static IcuEnvironment *env = new IcuEnvironment;

constexpr size_t kMaxInitialSize = 64;
constexpr size_t kMaxReserveSize = 4096;
constexpr size_t kMaxAppendLength = 64;
constexpr size_t kMaxAdditionalDesiredSize = 4096;

constexpr size_t kScratchBufSize = 4096;
char16_t scratch_buf[kScratchBufSize];

enum class AppendableApi { AppendCodeUnit, AppendCodePoint, AppendString, ReserveAppendCapacity, GetAppendBuffer, kMaxValue = GetAppendBuffer };

// Entry point for LibFuzzer.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider provider(data, size);
  auto str(icu::UnicodeString::fromUTF8(provider.ConsumeRandomLengthString(kMaxInitialSize)));
  icu::UnicodeStringAppendable strAppendable(str);

  while (provider.remaining_bytes() > 0) {
    switch (provider.ConsumeEnum<AppendableApi>()) {
    case AppendableApi::AppendCodeUnit:
      strAppendable.appendCodeUnit(provider.ConsumeIntegral<char16_t>());
      break;
    case AppendableApi::AppendCodePoint:
      strAppendable.appendCodePoint(provider.ConsumeIntegral<UChar32>());
      break;
    case AppendableApi::AppendString: {
      std::string appendChrs8(provider.ConsumeRandomLengthString(kMaxAppendLength));
      if (appendChrs8.size() == 0)
        break;
      std::vector<char16_t> appendChrs(RandomChar16Array(2, reinterpret_cast<const uint8_t *>(appendChrs8.data()), appendChrs8.size()));
      strAppendable.appendString(appendChrs.data(), appendChrs.size());
      break;
    }
    case AppendableApi::ReserveAppendCapacity:
      strAppendable.reserveAppendCapacity(provider.ConsumeIntegralInRange<int32_t>(0, kMaxReserveSize));
      break;
    case AppendableApi::GetAppendBuffer: {
      int32_t out_capacity;
      const auto min_capacity = provider.ConsumeIntegralInRange<int32_t>(1, kScratchBufSize);
      char16_t *out_buffer = strAppendable.getAppendBuffer(min_capacity, min_capacity + provider.ConsumeIntegralInRange<int32_t>(0, kMaxAdditionalDesiredSize), scratch_buf, kScratchBufSize, &out_capacity);
      // Write arbitrary value at the end of the buffer.
      if (out_buffer)
        out_buffer[out_capacity - 1] = 1;
      break;
    }
    }
  }

  return 0;
}
