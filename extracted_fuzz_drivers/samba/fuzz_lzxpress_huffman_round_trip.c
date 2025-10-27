/*
   Fuzzing for lzxpress_huffman{_decompress,_compress} round trip
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

int LLVMFuzzerTestOneInput(const uint8_t *buf, size_t len) {
  /*
   * we allow compressed to be 25% bigger than decompressed.
   */
  static uint8_t compressed[1024 * (1024 + 256)];
  static uint8_t decompressed[1024 * 1024];
  ssize_t compressed_size;
  ssize_t decompressed_size;
  struct lzxhuff_compressor_mem cmp;

  if (len > sizeof(decompressed) || len == 0) {
    return 0;
  }

  compressed_size = lzxpress_huffman_compress(&cmp, buf, len, compressed, sizeof(compressed));
  if (compressed_size < 0) {
    abort();
  }

  decompressed_size = lzxpress_huffman_decompress(compressed, compressed_size, decompressed, len);

  if (decompressed_size != len) {
    abort();
  }
  if (memcmp(buf, decompressed, len) != 0) {
    abort();
  }

  return 0;
}
