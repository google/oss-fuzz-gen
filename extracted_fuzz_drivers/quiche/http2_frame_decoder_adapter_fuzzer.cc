#include <cstddef>
#include <cstdint>

#include "quiche/spdy/core/http2_frame_decoder_adapter.h"
#include "quiche/spdy/core/spdy_no_op_visitor.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  spdy::SpdyNoOpVisitor visitor;
  http2::Http2DecoderAdapter decoder;
  decoder.set_visitor(&visitor);
  decoder.ProcessInput(reinterpret_cast<const char *>(data), size);
  return 0; // Always return 0; other values are reserved for future uses.
}
