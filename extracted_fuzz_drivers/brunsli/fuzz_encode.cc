// Copyright (c) Google LLC 2019
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

// #include "gtest/gtest.h"
// #include "testing/fuzzing/fuzztest.h"
#include "./test_utils.h"
#include <brunsli/brunsli_decode.h>
#include <brunsli/brunsli_encode.h>
#include <brunsli/jpeg_data.h>
#include <brunsli/jpeg_data_reader.h>
#include <brunsli/jpeg_data_writer.h>
#include <brunsli/status.h>

int DoTestOneInput(const uint8_t *data, size_t size) {
  // Encode.
  std::unique_ptr<brunsli::JPEGData> enc_jpg(new brunsli::JPEGData);
  // TODO(eustas): read header and skip if too many pixels are to be decoded.
  if (!brunsli::ReadJpeg(data, size, brunsli::JPEG_READ_ALL, enc_jpg.get())) {
    return 0;
  }
  size_t enc_output_size = brunsli::GetMaximumBrunsliEncodedSize(*enc_jpg);
  if (enc_output_size > (100 << 20)) {
    // Too many pixels; skip.
    return 0;
  }
  // We do not expect that Brunsli output is bigger than JPEG input.
  enc_output_size = std::min<size_t>(enc_output_size, size + (16 << 20));

  std::vector<uint8_t> enc_output(enc_output_size);
  bool enc_ok = brunsli::BrunsliEncodeJpeg(*enc_jpg, enc_output.data(), &enc_output_size);
  enc_jpg.reset();
  if (!enc_ok) {
    // It is OK, when regular encoder fails.
    // BrunsliEncodeJpegBypass could be used to wrap "broken" JPEGs.
    return 0;
  }
  enc_output.resize(enc_output_size);

  // Decode.
  brunsli::JPEGData dec_jpg;
  brunsli::BrunsliStatus dec_status;
  dec_status = brunsli::BrunsliDecodeJpeg(enc_output.data(), enc_output_size, &dec_jpg);
  if (dec_status != brunsli::BRUNSLI_OK) {
    __builtin_trap();
  }
  std::string dec_output;
  brunsli::JPEGOutput dec_out(brunsli::StringOutputFunction, &dec_output);
  bool dec_ok = brunsli::WriteJpeg(dec_jpg, dec_out);
  if (!dec_ok) {
    __builtin_trap();
  }

  // Compare.
  if (dec_output.size() != size) {
    __builtin_trap();
  }
  const uint8_t *dec_data = reinterpret_cast<const uint8_t *>(dec_output.data());
  for (size_t i = 0; i < size; ++i) {
    if (data[i] != dec_data[i]) {
      __builtin_trap();
    }
  }

  return 0;
}

// Entry point for LibFuzzer.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) { return DoTestOneInput(data, size); }

void TestOneInput(const std::vector<uint8_t> &data) { DoTestOneInput(data.data(), data.size()); }

std::vector<std::tuple<std::vector<uint8_t>>> ReadSeeds() {
  const std::vector<uint8_t> data = brunsli::ReadTestData("fuzz-encode.mar");
  return brunsli::ParseMar(data.data(), data.size());
}

FUZZ_TEST(BrunsliEncodeFuzz, TestOneInput).WithSeeds(ReadSeeds);

// TODO(eustas): Add existing cases.
TEST(BrunsliEncodeFuzz, Empty) { DoTestOneInput(nullptr, 0); }
