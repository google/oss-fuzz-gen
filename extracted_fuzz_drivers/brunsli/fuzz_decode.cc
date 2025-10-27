// Copyright (c) Google LLC 2019
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

#include <cstddef>
#include <cstdint>
#include <vector>

// #include "gtest/gtest.h"
// #include "testing/fuzzing/fuzztest.h"
#include "../common/platform.h"
#include "./test_utils.h"
#include <brunsli/brunsli_decode.h>
#include <brunsli/jpeg_data.h>
#include <brunsli/jpeg_data_writer.h>
#include <brunsli/status.h>

size_t DiscardOutputFunction(void *data, const uint8_t *buf, size_t count) {
  BRUNSLI_UNUSED(data);
  BRUNSLI_UNUSED(buf);
  return count;
}

int DoTestOneInput(const uint8_t *data, size_t size) {
  brunsli::JPEGOutput out(DiscardOutputFunction, nullptr);
  brunsli::JPEGData jpg;
  brunsli::BrunsliStatus status;
  status = brunsli::BrunsliDecodeJpeg(data, size, &jpg);
  if (status == brunsli::BRUNSLI_OK) {
    brunsli::WriteJpeg(jpg, out);
  }
  return 0;
}

// Entry point for LibFuzzer.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) { return DoTestOneInput(data, size); }

void TestOneInput(const std::vector<uint8_t> &data) { DoTestOneInput(data.data(), data.size()); }

std::vector<std::tuple<std::vector<uint8_t>>> ReadSeeds() {
  const std::vector<uint8_t> data = brunsli::ReadTestData("fuzz-decode.mar");
  return brunsli::ParseMar(data.data(), data.size());
}

FUZZ_TEST(BrunsliDecodeFuzz, TestOneInput).WithSeeds(ReadSeeds);

// TODO(eustas): Add existing cases.
TEST(BrunsliDecodeFuzz, Empty) { DoTestOneInput(nullptr, 0); }
