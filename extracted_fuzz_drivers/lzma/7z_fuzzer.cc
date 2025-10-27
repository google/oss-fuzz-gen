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

#include "7z.h"
#include "7zCrc.h"

#include "common-alloc.h"
#include "common-buffer.h"

// Limit maximum size to avoid running into timeouts with too large data.
static const size_t kMaxInputSize = 100 * 1024;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size > kMaxInputSize) {
    return 0;
  }

  CSzArEx db;
  SRes res;
  UInt16 *temp = nullptr;
  size_t tempSize = 0;
  UInt32 blockIndex = 0xFFFFFFFF; /* it can have any value before first call (if outBuffer = 0) */
  Byte *outBuffer = 0;            /* it must be 0 before first call for each new archive. */
  size_t outBufferSize = 0;       /* it can have any value before first call (if outBuffer = 0) */

  CrcGenerateTable();
  SzArEx_Init(&db);

  InputLookBuffer buffer(data, size);
  res = SzArEx_Open(&db, buffer.stream(), &CommonAlloc, &CommonAlloc);
  if (res != SZ_OK) {
    goto exit;
  }

  for (UInt32 i = 0; i < db.NumFiles; i++) {
    size_t offset = 0;
    size_t outSizeProcessed = 0;

    int isDir = SzArEx_IsDir(&db, i);
    size_t len = SzArEx_GetFileNameUtf16(&db, i, NULL);
    if (len > tempSize) {
      free(temp);
      tempSize = len;
      temp = (UInt16 *)malloc(tempSize * sizeof(temp[0]));
      if (!temp) {
        break;
      }
    }

    SzArEx_GetFileNameUtf16(&db, i, temp);
    SzArEx_GetFileSize(&db, i);
    if (isDir) {
      continue;
    }

    SzArEx_Extract(&db, buffer.stream(), i, &blockIndex, &outBuffer, &outBufferSize, &offset, &outSizeProcessed, &CommonAlloc, &CommonAlloc);
  }
  ISzAlloc_Free(&CommonAlloc, outBuffer);

exit:
  SzArEx_Free(&db, &CommonAlloc);
  free(temp);
  return 0;
}
