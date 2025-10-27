/*
   Fuzzing for lzxpress_huffman_compress_talloc
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

#define MAX_SIZE (1024 * 1024)

int LLVMFuzzerTestOneInput(const uint8_t *buf, size_t len) {
  static uint8_t *output;
  size_t output_len;
  TALLOC_CTX *mem_ctx = NULL;
  struct lzxhuff_compressor_mem cmp_mem;

  /*
   * The round-trip fuzzer checks the compressor with an unconstrained
   * output buffer; here we see what happens if the buffer is possibly too
   * small.
   */
  if (len < 3) {
    return 0;
  }
  output_len = MIN(MAX_SIZE, buf[0] | (buf[1] << 8) | (buf[2] << 16));
  buf += 3;
  len -= 3;
  mem_ctx = talloc_new(NULL);

  output = talloc_array(mem_ctx, uint8_t, output_len);

  lzxpress_huffman_compress(&cmp_mem, buf, len, output, output_len);

  talloc_free(mem_ctx);
  return 0;
}
