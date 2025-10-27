/*
   Fuzzing for lzxpress_decompress
   Copyright (C) Michael Hanselmann 2019
   Copyright (C) Douglas Bagnall 2022 <dbagnall@samba.org>

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "compression/lzxpress_huffman.h"
#include "fuzzing/fuzzing.h"
#include "includes.h"

int LLVMFuzzerInitialize(int *argc, char ***argv) { return 0; }

static uint8_t output[1024 * 1024] = {0};

int LLVMFuzzerTestOneInput(const uint8_t *buf, size_t len) {
  size_t target_len;
  if (len < 4) {
    return 0;
  }
  /*
   * An exact target length is required, which we store in the first 24
   * bits.
   */
  target_len = MIN(sizeof(output), buf[0] | (buf[1] << 8) | (buf[2] << 16));
  buf += 3;
  len -= 3;

  lzxpress_huffman_decompress(buf, len, output, target_len);

  return 0;
}
