// Copyright 2018 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <fuzzer/FuzzedDataProvider.h>

#include <cstddef>
#include <cstdint>

#include "quiche/quic/core/qpack/qpack_decoder_stream_sender.h"
#include "quiche/quic/core/quic_types.h"
#include "quiche/quic/test_tools/qpack/qpack_test_utils.h"

namespace quic {
namespace test {

// This fuzzer exercises QpackDecoderStreamSender.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  NoopQpackStreamSenderDelegate delegate;
  QpackDecoderStreamSender sender;
  sender.set_qpack_stream_sender_delegate(&delegate);

  FuzzedDataProvider provider(data, size);

  while (provider.remaining_bytes() != 0) {
    switch (provider.ConsumeIntegral<uint8_t>() % 4) {
    case 0: {
      uint64_t increment = provider.ConsumeIntegral<uint64_t>();
      sender.SendInsertCountIncrement(increment);
      break;
    }
    case 1: {
      QuicStreamId stream_id = provider.ConsumeIntegral<QuicStreamId>();
      sender.SendHeaderAcknowledgement(stream_id);
      break;
    }
    case 2: {
      QuicStreamId stream_id = provider.ConsumeIntegral<QuicStreamId>();
      sender.SendStreamCancellation(stream_id);
      break;
    }
    case 3: {
      sender.Flush();
      break;
    }
    }
  }

  sender.Flush();
  return 0;
}

} // namespace test
} // namespace quic
