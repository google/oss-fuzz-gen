#include <cstddef>
#include <cstdint>

#include "quiche/http2/decoder/decode_buffer.h"
#include "quiche/http2/decoder/http2_frame_decoder.h"
#include "quiche/http2/decoder/http2_frame_decoder_listener.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  http2::Http2FrameDecoderNoOpListener listener;
  http2::Http2FrameDecoder decoder(&listener);
  http2::DecodeBuffer db(reinterpret_cast<const char *>(data), size);
  decoder.DecodeFrame(&db);
  return 0; // Always return 0; other values are reserved for future uses.
}
