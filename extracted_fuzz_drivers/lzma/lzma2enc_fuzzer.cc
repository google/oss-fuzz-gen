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

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "Lzma2Dec.h"
#include "Lzma2Enc.h"

#include "common-alloc.h"
#include "common-buffer.h"

// Limit maximum size to avoid running into timeouts with too large data.
static const size_t kMaxInputSize = 100 * 1024;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size <= 10 || size > kMaxInputSize) {
    return 0;
  }

  CLzma2EncProps props;
  Byte props_data;

  memset(&props, 0, sizeof(props));
  Lzma2EncProps_Init(&props);
  props.lzmaProps.level = data[0] <= 9 ? data[0] : 9;
  props.lzmaProps.lc = data[1] <= 8 ? data[1] : 8;
  props.lzmaProps.lp = data[2] <= 4 ? data[2] : 4;
  props.lzmaProps.pb = data[3] <= 4 ? data[3] : 4;
  props.lzmaProps.algo = data[4] ? 1 : 0;
  props.lzmaProps.fb = 5 + data[5];
  props.lzmaProps.btMode = data[6] ? 1 : 0;
  props.lzmaProps.numHashBytes = 2 + (data[7] % 3);
  props.lzmaProps.mc = 1 + data[8];
  props.lzmaProps.writeEndMark = data[9] ? 1 : 0;
  props.lzmaProps.dictSize = 1 << 24;
  data += 10;
  size -= 10;
  Lzma2EncProps_Normalize(&props);

  CLzma2EncHandle enc = Lzma2Enc_Create(&CommonAlloc, &CommonAlloc);
  if (!enc) {
    return 0;
  }

  OutputBuffer out_buffer;
  InputBuffer in_buffer(data, size);
  Byte *dest = nullptr;
  SizeT srcLen;
  SizeT destLen;
  ELzmaStatus status;

  SRes res = Lzma2Enc_SetProps(enc, &props);
  if (res != SZ_OK) {
    goto exit;
  }

  Lzma2Enc_SetDataSize(enc, size);
  props_data = Lzma2Enc_WriteProperties(enc);

  res = Lzma2Enc_Encode2(enc, out_buffer.stream(), nullptr, 0, in_buffer.stream(), nullptr, 0, nullptr);
  assert(res == SZ_OK);
  assert(out_buffer.size() > 0);

  // Decompress and compare with input data.
  dest = static_cast<Byte *>(malloc(size));
  assert(dest);
  destLen = size;
  srcLen = out_buffer.size();

  res = Lzma2Decode(dest, &destLen, out_buffer.data(), &srcLen, props_data, LZMA_FINISH_END, &status, &CommonAlloc);
  assert(res == SZ_OK);
  assert(status == LZMA_STATUS_FINISHED_WITH_MARK || status == LZMA_STATUS_MAYBE_FINISHED_WITHOUT_MARK);
  assert(srcLen == out_buffer.size());
  assert(memcmp(dest, data, size) == 0);

exit:
  Lzma2Enc_Destroy(enc);
  free(dest);
  return 0;
}
