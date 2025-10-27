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
#include <deque>
#include <memory>
#include <vector>

#include "examples/file_reader.h"
#include "examples/file_reader_constants.h"
#include "examples/file_reader_interface.h"
#include "src/gav1/decoder.h"
#include "src/gav1/status_code.h"
#include "tests/fuzzer/fuzzer_temp_file.h"

namespace {

#if defined(LIBGAV1_EXHAUSTIVE_FUZZING)
// Set a large upper bound to give more coverage of a single input; this value
// should be larger than most of the frame counts in the corpus.
constexpr size_t kMaxDataSize = 400 * 1024;
#else
constexpr size_t kMaxDataSize = 200 * 1024;
#endif

using InputBuffer = std::vector<uint8_t>;

struct InputBuffers {
  ~InputBuffers() {
    for (auto &buffer : free_buffers) {
      delete buffer;
    }
  }
  std::deque<InputBuffer *> free_buffers;
};

void ReleaseInputBuffer(void *callback_private_data, void *buffer_private_data) {
  auto *const test = static_cast<InputBuffers *>(callback_private_data);
  test->free_buffers.push_back(static_cast<InputBuffer *>(buffer_private_data));
}

} // namespace

// Always returns 0. Nonzero return values are reserved by libFuzzer for future
// use.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  // Reject large chunks of data to improve fuzzer throughput.
  if (size > kMaxDataSize)
    return 0;

  // Note that |input_buffers| has to outlive the |decoder| object since the
  // |release_input_buffer| callback could be called on the |decoder|'s
  // destructor.
  InputBuffers input_buffers;

  libgav1::Decoder decoder;
  libgav1::DecoderSettings settings = {};
  // Use the 33 + low byte of the width to seed the number of threads. This
  // ensures that we will trigger the frame parallel path in most cases.
  // We use both nibbles of the lower byte as this results in values != 1 much
  // more quickly than using the lower nibble alone.
  settings.threads = 33 + ((size >= 13) ? ((data[12] >> 4 | data[12]) & 0xF) + 1 : 1);

  settings.frame_parallel = true;
  settings.blocking_dequeue = true;
  settings.callback_private_data = &input_buffers;
  settings.release_input_buffer = ReleaseInputBuffer;
  if (decoder.Init(&settings) != libgav1::kStatusOk)
    return 0;

  FuzzerTemporaryFile tempfile(data, size);
  auto file_reader = libgav1::FileReader::Open(tempfile.filename(), /*error_tolerant=*/true);
  if (file_reader == nullptr)
    return 0;

  InputBuffer *input_buffer = nullptr;
  bool dequeue_finished = false;

  do {
    if (input_buffer == nullptr && !file_reader->IsEndOfFile()) {
      if (input_buffers.free_buffers.empty()) {
        auto *const buffer = new (std::nothrow) InputBuffer();
        if (buffer == nullptr) {
          break;
        }
        input_buffers.free_buffers.push_back(buffer);
      }
      input_buffer = input_buffers.free_buffers.front();
      input_buffers.free_buffers.pop_front();
      if (!file_reader->ReadTemporalUnit(input_buffer, nullptr)) {
        break;
      }
    }

    if (input_buffer != nullptr) {
      libgav1::StatusCode status = decoder.EnqueueFrame(input_buffer->data(), input_buffer->size(),
                                                        /*user_private_data=*/0,
                                                        /*buffer_private_data=*/input_buffer);
      if (status == libgav1::kStatusOk) {
        input_buffer = nullptr;
        // Continue to enqueue frames until we get a kStatusTryAgain status.
        continue;
      }
      if (status != libgav1::kStatusTryAgain) {
        break;
      }
    }

    const libgav1::DecoderBuffer *buffer;
    libgav1::StatusCode status = decoder.DequeueFrame(&buffer);
    if (status == libgav1::kStatusNothingToDequeue) {
      dequeue_finished = true;
    } else if (status == libgav1::kStatusOk) {
      dequeue_finished = false;
    } else {
      break;
    }
  } while (input_buffer != nullptr || !file_reader->IsEndOfFile() || !dequeue_finished);

  if (input_buffer != nullptr) {
    input_buffers.free_buffers.push_back(input_buffer);
  }

  return 0;
}
