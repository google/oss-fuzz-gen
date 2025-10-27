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
#include "src/buffer_pool.h"
#include "src/decoder_impl.h"
#include "src/decoder_state.h"
#include "src/internal_frame_buffer_list.h"
#include "src/obu_parser.h"
#include "tests/fuzzer/fuzzer_temp_file.h"

namespace {

#if defined(LIBGAV1_EXHAUSTIVE_FUZZING)
// Set a large upper bound to give more coverage of a single input; this value
// should be larger than most of the frame counts in the corpus.
constexpr int kMaxFrames = 100;
constexpr size_t kMaxDataSize = 400 * 1024;
#else
// Restrict the number of frames and obus to improve fuzzer throughput.
constexpr int kMaxFrames = 5;
constexpr size_t kMaxDataSize = 200 * 1024;
#endif

inline void ParseObu(const uint8_t *const data, size_t size) {
  size_t av1c_size;
  const std::unique_ptr<uint8_t[]> av1c_box = libgav1::ObuParser::GetAV1CodecConfigurationBox(data, size, &av1c_size);
  static_cast<void>(av1c_box);

  libgav1::InternalFrameBufferList buffer_list;
  libgav1::BufferPool buffer_pool(libgav1::OnInternalFrameBufferSizeChanged, libgav1::GetInternalFrameBuffer, libgav1::ReleaseInternalFrameBuffer, &buffer_list);
  libgav1::DecoderState decoder_state;
  libgav1::ObuParser parser(data, size, 0, &buffer_pool, &decoder_state);
  libgav1::RefCountedBufferPtr current_frame;
  int parsed_frames = 0;
  while (parser.HasData()) {
    if (parser.ParseOneFrame(&current_frame) != libgav1::kStatusOk)
      break;
    if (++parsed_frames >= kMaxFrames)
      break;
  }
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  // Reject large chunks of data to improve fuzzer throughput.
  if (size > kMaxDataSize)
    return 0;

  // Treat the input as a raw OBU stream.
  ParseObu(data, size);

  // Use the first frame from an IVF to bypass any read errors from the parser.
  static constexpr size_t kIvfHeaderSize = libgav1::kIvfFileHeaderSize + libgav1::kIvfFrameHeaderSize;
  if (size >= kIvfHeaderSize) {
    ParseObu(data + kIvfHeaderSize, size - kIvfHeaderSize);
  }

  FuzzerTemporaryFile tempfile(data, size);
  auto file_reader = libgav1::FileReader::Open(tempfile.filename(), /*error_tolerant=*/true);
  if (file_reader == nullptr)
    return 0;

  std::vector<uint8_t> buffer;
  int parsed_frames = 0;
  do {
    if (!file_reader->ReadTemporalUnit(&buffer, nullptr))
      break;
    ParseObu(buffer.data(), buffer.size());
    if (++parsed_frames >= kMaxFrames)
      break;
  } while (!file_reader->IsEndOfFile());

  return 0;
}
