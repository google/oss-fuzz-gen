// Copyright 2018 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <fuzzer/FuzzedDataProvider.h>

#include <cstddef>
#include <cstdint>
#include <limits>

#include "absl/strings/string_view.h"
#include "quiche/quic/core/qpack/qpack_decoder_stream_receiver.h"
#include "quiche/quic/core/quic_error_codes.h"
#include "quiche/quic/core/quic_stream.h"

namespace quic {
namespace test {
namespace {

// A QpackDecoderStreamReceiver::Delegate implementation that ignores all
// decoded instructions but keeps track of whether an error has been detected.
class NoOpDelegate : public QpackDecoderStreamReceiver::Delegate {
public:
  NoOpDelegate() : error_detected_(false) {}
  ~NoOpDelegate() override = default;

  void OnInsertCountIncrement(uint64_t /*increment*/) override {}
  void OnHeaderAcknowledgement(QuicStreamId /*stream_id*/) override {}
  void OnStreamCancellation(QuicStreamId /*stream_id*/) override {}
  void OnErrorDetected(QuicErrorCode /*error_code*/, absl::string_view /*error_message*/) override { error_detected_ = true; }

  bool error_detected() const { return error_detected_; }

private:
  bool error_detected_;
};

} // namespace

// This fuzzer exercises QpackDecoderStreamReceiver.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  NoOpDelegate delegate;
  QpackDecoderStreamReceiver receiver(&delegate);

  FuzzedDataProvider provider(data, size);

  while (!delegate.error_detected() && provider.remaining_bytes() != 0) {
    // Process up to 64 kB fragments at a time.  Too small upper bound might not
    // provide enough coverage, too large might make fuzzing too inefficient.
    size_t fragment_size = provider.ConsumeIntegralInRange<uint16_t>(0, std::numeric_limits<uint16_t>::max());
    receiver.Decode(provider.ConsumeRandomLengthString(fragment_size));
  }

  return 0;
}

} // namespace test
} // namespace quic
