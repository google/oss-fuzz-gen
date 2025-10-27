#include <Common/Exception.h>
#include <Compression/CompressedReadBuffer.h>
#include <IO/ReadBufferFromMemory.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  try {
    DB::ReadBufferFromMemory from(data, size);
    DB::CompressedReadBuffer in{from};

    while (!in.eof())
      in.next();
  } catch (...) {
  }

  return 0;
}
