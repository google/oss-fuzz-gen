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
#include "XzEnc.h"

#include "common-alloc.h"
#include "common-buffer.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 3) {
    return 0;
  }

  CrcGenerateTable();
  Crc64GenerateTable();

  SRes res;
  CXzProps props;
  XzProps_Init(&props);

  switch (data[0]) {
  case XZ_CHECK_NO:
  case XZ_CHECK_CRC32:
  case XZ_CHECK_CRC64:
  case XZ_CHECK_SHA256:
    props.checkId = data[0];
    break;
  }

  switch (data[1]) {
  case XZ_ID_X86:
  case XZ_ID_PPC:
  case XZ_ID_IA64:
  case XZ_ID_ARM:
  case XZ_ID_ARMT:
  case XZ_ID_SPARC:
    props.filterProps.id = data[1];
    props.filterProps.ipDefined = True;
    break;
  case XZ_ID_Delta:
    props.filterProps.id = data[1];
    props.filterProps.delta = data[2];
    if (props.filterProps.delta == 0) {
      return 0;
    }
    break;
  }

  OutputBuffer out_buffer;
  InputBuffer in_buffer(data, size);
  CXzEncHandle enc;
  enc = XzEnc_Create(&CommonAlloc, &CommonAlloc);
  if (XzEnc_SetProps(enc, &props) != SZ_OK) {
    goto exit;
  }

  XzEnc_SetDataSize(enc, size);
  res = XzEnc_Encode(enc, out_buffer.stream(), in_buffer.stream(), nullptr);
  assert(res == SZ_OK);

  {
    // Decompress and compare with input data.
    CXzDecMtProps dec_props;
    XzDecMtProps_Init(&dec_props);

    OutputBuffer dec_out_buffer;
    InputBuffer dec_in_buffer(out_buffer.data(), out_buffer.size());
    CXzStatInfo stats;
    int isMt;

    CXzDecMtHandle dec = XzDecMt_Create(&CommonAlloc, &CommonAlloc);
    res = XzDecMt_Decode(dec, &dec_props, nullptr, 1, dec_out_buffer.stream(), dec_in_buffer.stream(), &stats, &isMt, nullptr);
    assert(res == SZ_OK);
    assert(dec_out_buffer.size() == size);
    assert(memcmp(data, dec_out_buffer.data(), size) == 0);
    XzDecMt_Destroy(dec);
  }

exit:
  XzEnc_Destroy(enc);
  return 0;
}
