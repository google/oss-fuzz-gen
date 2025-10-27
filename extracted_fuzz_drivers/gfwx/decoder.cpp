/* By Guido Vranken <guidovranken@gmail.com> */

#include "fuzzing/memory.hpp"
#include "gfwx.h"
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstring>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  GFWX::Header header;

  {
    ptrdiff_t result = GFWX::decompress((uint8_t *)0, header, data, size, 0, true);
    if (result != GFWX::ResultOk) {
      return 0;
    }
  }

  if (header.bitDepth > 32) {
    return 0;
  }
  if (header.channels > 10) {
    return 0;
  }
  if (header.layers > 10) {
    return 0;
  }
  if (header.sizex > 10240) {
    return 0;
  }
  if (header.sizey > 10240) {
    return 0;
  }

  {
    const size_t totalOutSize = (header.bitDepth / 8) * header.channels * header.layers * header.sizex * header.sizey;
    if (totalOutSize > (1024 * 1024)) {
      return 0;
    }
    std::vector<uint8_t> out(totalOutSize);
    ptrdiff_t result = GFWX::decompress(out.data(), header, data, size, 0, false);
    if (result != GFWX::ResultOk) {
      return 0;
    }
    fuzzing::memory::memory_test(out);
  }

  return 0;
}
