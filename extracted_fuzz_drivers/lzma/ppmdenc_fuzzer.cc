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

#include "Ppmd7.h"

#include "common-alloc.h"
#include "common-buffer.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size <= 10) {
    return 0;
  }

  CPpmd7 p_enc;
  Ppmd7_Construct(&p_enc);
  UInt32 memsize = PPMD7_MIN_MEM_SIZE;
  if (!Ppmd7_Alloc(&p_enc, memsize, &CommonAlloc)) {
    return 0;
  }

  int order = data[0];
  if (order < PPMD7_MIN_ORDER || order > PPMD7_MAX_ORDER) {
    Ppmd7_Free(&p_enc, &CommonAlloc);
    return 0;
  }
  Ppmd7_Init(&p_enc, order);

  OutputByteBuffer out_buffer;
  CPpmd7z_RangeEnc enc;
  Ppmd7z_RangeEnc_Init(&enc);
  enc.Stream = out_buffer.stream();
  for (size_t i = 0; i < size; ++i) {
    Ppmd7_EncodeSymbol(&p_enc, &enc, data[i]);
  }
  Ppmd7z_RangeEnc_FlushData(&enc);
  Ppmd7_Free(&p_enc, &CommonAlloc);

  {
    assert(out_buffer.size() >= 5);
    InputByteBuffer in_buffer(out_buffer.data(), out_buffer.size());
    CPpmd7 p_dec;
    Ppmd7_Construct(&p_dec);
    assert(Ppmd7_Alloc(&p_dec, memsize, &CommonAlloc));
    Ppmd7_Init(&p_dec, order);
    CPpmd7z_RangeDec dec;
    Ppmd7z_RangeDec_CreateVTable(&dec);
    dec.Stream = in_buffer.stream();
    assert(Ppmd7z_RangeDec_Init(&dec));

    for (size_t i = 0; i < size; ++i) {
      int sym = Ppmd7_DecodeSymbol(&p_dec, &dec.vt);
      assert(sym >= 0);
      assert(sym == data[i]);
    }
    Ppmd7_Free(&p_dec, &CommonAlloc);
  }
  return 0;
}
