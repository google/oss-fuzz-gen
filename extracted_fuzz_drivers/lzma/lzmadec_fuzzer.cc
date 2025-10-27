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

#include "LzmaDec.h"

#include "common-alloc.h"

static const size_t kBufferSize = 8192;

static const size_t kMaxDictionarySize = 32 * 1024 * 1024;

// Limit maximum size to avoid running into timeouts with too large data.
static const size_t kMaxInputSize = 100 * 1024;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < LZMA_PROPS_SIZE || size > kMaxInputSize) {
    return 0;
  }

  CLzmaProps props;
  if (LzmaProps_Decode(&props, data, LZMA_PROPS_SIZE) != SZ_OK) {
    return 0;
  }

  // Avoid using too much memory.
  if (props.dicSize > kMaxDictionarySize) {
    return 0;
  }

  CLzmaDec dec;
  LzmaDec_Construct(&dec);
  if (LzmaDec_Allocate(&dec, data, LZMA_PROPS_SIZE, &CommonAlloc) != SZ_OK) {
    return 0;
  }

  data += LZMA_PROPS_SIZE;
  size -= LZMA_PROPS_SIZE;

  LzmaDec_Init(&dec);
  while (size > 0) {
    Byte buf[kBufferSize];
    SRes res;
    SizeT srcLen = size;
    SizeT destLen = kBufferSize;
    ELzmaStatus status;
    res = LzmaDec_DecodeToBuf(&dec, buf, &destLen, data, &srcLen, LZMA_FINISH_ANY, &status);
    if (res != SZ_OK || status == LZMA_STATUS_FINISHED_WITH_MARK || status == LZMA_STATUS_NEEDS_MORE_INPUT) {
      goto exit;
    }

    size -= srcLen;
    data += srcLen;
  }

exit:
  LzmaDec_Free(&dec, &CommonAlloc);
  return 0;
}
