/*
   Fuzzing for lzxpress_decompress
   Copyright (C) Michael Hanselmann 2019

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

#include "fuzzing/fuzzing.h"
#include "includes.h"
#include "lzxpress.h"

int LLVMFuzzerInitialize(int *argc, char ***argv) { return 0; }

int LLVMFuzzerTestOneInput(const uint8_t *buf, size_t len) {
  static uint8_t compressed[1024 * 1280] = {0};
  static uint8_t decompressed[1024 * 1024] = {0};
  ssize_t compressed_size;
  ssize_t decompressed_size;

  if (len > sizeof(decompressed)) {
    return 0;
  }

  compressed_size = lzxpress_compress(buf, len, compressed, sizeof(compressed));
  if (compressed_size < 0) {
    abort();
  }

  decompressed_size = lzxpress_decompress(compressed, compressed_size, decompressed, sizeof(decompressed));

  if (decompressed_size != len) {
    abort();
  }
  if (memcmp(buf, decompressed, len) != 0) {
    abort();
  }

  return 0;
}
