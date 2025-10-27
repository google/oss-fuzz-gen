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

// This file implements a basic fuzz test for the Detokenizer.
// An instance of the Detokenizer is created from a minimal, nearly-empty token
// database. Fuzz data is fed to the detokenizer in various supported input
// argument formats at random, when then decodes this data and tries to match
// it to tokens in the database.

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <vector>

#include "pw_fuzzer/fuzzed_data_provider.h"
#include "pw_preprocessor/util.h"
#include "pw_tokenizer/detokenize.h"

namespace pw::tokenizer {
namespace {

constexpr size_t kFuzzRangeMin = 0;
constexpr size_t kFuzzRangeMax = 10000;

enum DetokenizeBufferArgumentType : uint8_t { kSpan = 0, kStringView, kPtrAndLength, kMaxValue = kPtrAndLength };

// In order to better fuzz the detokenizer, rather than use an empty token
// database, we construct a minimal database with 4 entries out of a string
// literal array that matches the token database format (see token_database.h
// for detailed info on the database entry format)
constexpr char kBasicData[] = "TOKENS\0\0"
                              "\x04\x00\x00\x00"
                              "\0\0\0\0"
                              "\x01\x00\x00\x00----"
                              "\x05\x00\x00\x00----"
                              "\xFF\x00\x00\x00----"
                              "\xFF\xEE\xEE\xDD----"
                              "One\0"
                              "TWO\0"
                              "333\0"
                              "FOUR";

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  static Detokenizer detokenizer(TokenDatabase::Create<kBasicData>());

  FuzzedDataProvider provider(data, size);

  while (provider.remaining_bytes() != 0) {
    // Map the first word of the remaining fuzz data to a buffer argument
    // type, and feed the Detokenizer with a random length buffer to be
    // detokenized in the relevant format. The detokenized string returned
    // is itself of little consequence to this test.
    switch (provider.ConsumeEnum<DetokenizeBufferArgumentType>()) {
    case kSpan: {
      size_t consumed_size = provider.ConsumeIntegralInRange<size_t>(kFuzzRangeMin, kFuzzRangeMax);
      std::vector<uint8_t> buffer = provider.ConsumeBytes<uint8_t>(consumed_size);
      if (buffer.empty()) {
        return -1;
      }
      auto detokenized_string = detokenizer.Detokenize(span(&buffer[0], buffer.size()));
      static_cast<void>(detokenized_string);
      break;
    }

    case kStringView: {
      std::string str = provider.ConsumeRandomLengthString(provider.remaining_bytes());
      auto detokenized_string = detokenizer.Detokenize(str);
      static_cast<void>(detokenized_string);
      break;
    }

    case kPtrAndLength: {
      size_t consumed_size = provider.ConsumeIntegralInRange<size_t>(kFuzzRangeMin, kFuzzRangeMax);
      std::vector<uint8_t> buffer = provider.ConsumeBytes<uint8_t>(consumed_size);
      auto detokenized_string = detokenizer.Detokenize(buffer.data(), buffer.size());
      static_cast<void>(detokenized_string);
      break;
    }
    }
  }

  return 0;
}

} // namespace pw::tokenizer
