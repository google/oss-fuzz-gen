/**
 *
 * @copyright Copyright (c) 2019 Joachim Bauch <mail@joachim-bauch.de>
 *
 * @license GNU GPL version 3 or any later version
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "Lzma2Dec.h"

#include "common-alloc.h"

static const size_t kBufferSize = 8192;

static const size_t kMaxDictionarySize = 32 * 1024 * 1024;

// Limit maximum size to avoid running into timeouts with too large data.
static const size_t kMaxInputSize = 100 * 1024;

// Copied from sdk/C/Lzma2Dec.c
#define LZMA2_DIC_SIZE_FROM_PROP(p) (((UInt32)2 | ((p) & 1)) << ((p) / 2 + 11))

static bool GetDictionarySize(Byte prop, size_t *size) {
  if (prop > 40) {
    return false;
  }

  *size = (prop == 40) ? 0xFFFFFFFF : LZMA2_DIC_SIZE_FROM_PROP(prop);
  return true;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 1 || size > kMaxInputSize) {
    return 0;
  }

  size_t dictionarySize;
  if (!GetDictionarySize(data[0], &dictionarySize)) {
    return 0;
  }

  // Avoid using too much memory.
  if (dictionarySize > kMaxDictionarySize) {
    return 0;
  }

  CLzma2Dec dec;
  Lzma2Dec_Construct(&dec);
  if (Lzma2Dec_Allocate(&dec, data[0], &CommonAlloc) != SZ_OK) {
    return 0;
  }

  data += 1;
  size -= 1;

  Lzma2Dec_Init(&dec);
  while (size > 0) {
    Byte buf[kBufferSize];
    SRes res;
    SizeT srcLen = size;
    SizeT destLen = kBufferSize;
    ELzmaStatus status;
    res = Lzma2Dec_DecodeToBuf(&dec, buf, &destLen, data, &srcLen, LZMA_FINISH_ANY, &status);
    if (res != SZ_OK || status == LZMA_STATUS_FINISHED_WITH_MARK || status == LZMA_STATUS_NEEDS_MORE_INPUT) {
      goto exit;
    }

    size -= srcLen;
    data += srcLen;
  }

exit:
  Lzma2Dec_Free(&dec, &CommonAlloc);
  return 0;
}
