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

// This file implements a basic fuzz test for the TokenDatabase class
// A database is created from fuzz data, and a random entry count (also
// derived from the fuzz data) is set. We then run iterations and 'find'
// operations on this database.

#include <cstring>

#include "pw_fuzzer/asan_interface.h"
#include "pw_fuzzer/fuzzed_data_provider.h"
#include "pw_preprocessor/util.h"
#include "pw_span/span.h"
#include "pw_tokenizer/token_database.h"

namespace pw::tokenizer {
namespace {

enum FuzzTestType : uint8_t {
  kValidHeader,
  kRandomHeader,
  kMaxValue = kRandomHeader,
};

constexpr size_t kTokenHeaderSize = 16;

// The default max length in bytes of fuzzed data provided. Note that
// this needs to change if the fuzzer executable is run with a
// '-max_len' argument.
constexpr size_t kFuzzDataSizeMax = 4096;

// Location of the 'EntryCount' field in the token header.
constexpr size_t kEntryCountOffset = 8;
constexpr size_t kEntryCountSize = 4;

void SetTokenEntryCountInBuffer(uint8_t *buffer, uint32_t count) { memcpy(buffer + kEntryCountOffset, &count, kEntryCountSize); }

void IterateOverDatabase(TokenDatabase *const database) {
  for (TokenDatabase::Entry entry : *database) {
    // Since we don't "use" the contents of the entry, we exercise
    // the entry by extracting its contents into volatile variables
    // to prevent it from being optimized out during compilation.
    [[maybe_unused]] volatile const char *entry_string = entry.string;
    [[maybe_unused]] volatile uint32_t entry_token = entry.token;
  }
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  constexpr size_t kBufferSizeMax = kFuzzDataSizeMax + kTokenHeaderSize;
  constexpr char kDefaultHeader[] = "TOKENS\0\0\0\0\0\0\0\0\0";
  static uint8_t buffer[kBufferSizeMax];

  if (!data || size == 0 || size > kFuzzDataSizeMax) {
    return 0;
  }

  FuzzedDataProvider provider(data, size);

  // Initialize the token header with either a valid or invalid header
  // based on a random enum consumed from the fuzz data.
  switch (provider.ConsumeEnum<FuzzTestType>()) {
  case kValidHeader:
    memcpy(buffer, kDefaultHeader, kTokenHeaderSize);
    break;

  case kRandomHeader: {
    std::vector<uint8_t> random_header = provider.ConsumeBytes<uint8_t>(kTokenHeaderSize);
    random_header.resize(kTokenHeaderSize);
    memcpy(buffer, &random_header[0], kTokenHeaderSize);
    break;
  }
  }

  // Consume a 'test token' integer to look up later in the database.
  uint32_t random_token = provider.ConsumeIntegral<uint32_t>();

  // Consume a 'token count' integer to set as our database entry count.
  uint32_t random_token_count = provider.ConsumeIntegralInRange<uint32_t>(0, kFuzzDataSizeMax);

  // Consume the remaining data. Note that the data corresponding to the
  // string entries in the database are not explicitly null-terminated.
  // TODO(karthikmb): Once OSS-Fuzz updates to Clang11.0, switch to
  // provider.ConsumeData() to avoid extra memory and the memcpy call.
  auto consumed_bytes = provider.ConsumeBytes<uint8_t>(provider.remaining_bytes());
  memcpy(buffer + kTokenHeaderSize, &consumed_bytes[0], consumed_bytes.size());

  SetTokenEntryCountInBuffer(buffer, random_token_count);

  // Poison the unused buffer space for this run of the fuzzer to
  // prevent the token database creator from reading too far in.
  size_t data_size = kTokenHeaderSize + consumed_bytes.size();
  size_t poisoned_length = kBufferSizeMax - data_size;
  void *poisoned = &buffer[data_size];

  ASAN_POISON_MEMORY_REGION(poisoned, poisoned_length);

  // We create a database from a span of the buffer since the string
  // entries might not be null terminated, and the creation of a database
  // from a raw buffer has an explicit null terminated string requirement
  // specified in the API.
  span<uint8_t> data_span(buffer, data_size);
  auto token_database = TokenDatabase::Create<span<uint8_t>>(data_span);
  [[maybe_unused]] volatile auto match = token_database.Find(random_token);

  IterateOverDatabase(&token_database);

  // Un-poison for the next iteration.
  ASAN_UNPOISON_MEMORY_REGION(poisoned, poisoned_length);

  return 0;
}

} // namespace pw::tokenizer
