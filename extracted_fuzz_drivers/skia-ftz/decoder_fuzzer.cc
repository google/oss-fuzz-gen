// Copyright 2020 The libgav1 Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <cstddef>
#include <cstdint>
#include <memory>
#include <vector>

#include "examples/file_reader.h"
#include "examples/file_reader_constants.h"
#include "examples/file_reader_interface.h"
#include "src/gav1/decoder.h"
#include "tests/fuzzer/fuzzer_temp_file.h"

namespace {

#if defined(LIBGAV1_EXHAUSTIVE_FUZZING)
// Set a large upper bound to give more coverage of a single input; this value
// should be larger than most of the frame counts in the corpus.
constexpr int kMaxFrames = 100;
constexpr size_t kMaxDataSize = 400 * 1024;
#else
// Restrict the number of frames to improve fuzzer throughput.
constexpr int kMaxFrames = 5;
constexpr size_t kMaxDataSize = 200 * 1024;
#endif

void Decode(const uint8_t *const data, const size_t size, libgav1::Decoder *const decoder) {
  decoder->EnqueueFrame(data, size, /*user_private_data=*/0,
                        /*buffer_private_data=*/nullptr);
  const libgav1::DecoderBuffer *buffer;
  decoder->DequeueFrame(&buffer);
}

} // namespace

// Always returns 0. Nonzero return values are reserved by libFuzzer for future
// use.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  // Reject large chunks of data to improve fuzzer throughput.
  if (size > kMaxDataSize)
    return 0;

  libgav1::Decoder decoder;
  libgav1::DecoderSettings settings = {};
  // Use the low byte of the width to seed the number of threads.
  // We use both nibbles of the lower byte as this results in values != 1 much
  // more quickly than using the lower nibble alone.
  settings.threads = (size >= 13) ? ((data[12] >> 4 | data[12]) & 0xF) + 1 : 1;
  if (decoder.Init(&settings) != libgav1::kStatusOk)
    return 0;

  // Treat the input as a raw OBU stream.
  Decode(data, size, &decoder);

  // Use the first frame from an IVF to bypass any read errors from the parser.
  static constexpr size_t kIvfHeaderSize = libgav1::kIvfFileHeaderSize + libgav1::kIvfFrameHeaderSize;
  if (size >= kIvfHeaderSize) {
    Decode(data + kIvfHeaderSize, size - kIvfHeaderSize, &decoder);
  }

  FuzzerTemporaryFile tempfile(data, size);
  auto file_reader = libgav1::FileReader::Open(tempfile.filename(), /*error_tolerant=*/true);
  if (file_reader == nullptr)
    return 0;

  std::vector<uint8_t> buffer;
  int decoded_frames = 0;
  do {
    if (!file_reader->ReadTemporalUnit(&buffer, nullptr))
      break;
    Decode(buffer.data(), buffer.size(), &decoder);
    if (++decoded_frames >= kMaxFrames)
      break;
  } while (!file_reader->IsEndOfFile());

  return 0;
}
