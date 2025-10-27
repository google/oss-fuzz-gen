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

#include "7zCrc.h"
#include "Xz.h"
#include "XzCrc64.h"

#include "common-alloc.h"
#include "common-buffer.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  CrcGenerateTable();
  Crc64GenerateTable();

  CXzDecMtProps props;
  XzDecMtProps_Init(&props);

  OutputBuffer out_buffer;
  InputBuffer in_buffer(data, size);
  CXzStatInfo stats;
  int isMt;

  CXzDecMtHandle handle = XzDecMt_Create(&CommonAlloc, &CommonAlloc);
  XzDecMt_Decode(handle, &props, nullptr, 1, out_buffer.stream(), in_buffer.stream(), &stats, &isMt, nullptr);
  XzDecMt_Destroy(handle);
  return 0;
}
