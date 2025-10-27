/*
   Fuzzing ldb_binary_decode and ldb_binary_encode_string
   Copyright (C) Catalyst IT 2020

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
#include "ldb_private.h"

#define MAX_LENGTH (2 * 1024 * 1024 - 1)
char buf[MAX_LENGTH + 1] = {0};

static char *possibly_truncate(uint8_t *input, size_t len) {
  if (len > MAX_LENGTH) {
    len = MAX_LENGTH;
  }
  memcpy(buf, input, len);
  buf[len] = 0;
  return buf;
}

int LLVMFuzzerTestOneInput(const uint8_t *input, size_t len) {
  TALLOC_CTX *mem_ctx = talloc_init(__FUNCTION__);
  struct ldb_val val = {0};
  const char *s = possibly_truncate(input, len);

  /* we treat the same string to encoding and decoding, not
   * round-tripping. */
  val = ldb_binary_decode(mem_ctx, s);
  ldb_binary_encode_string(mem_ctx, s);
  TALLOC_FREE(mem_ctx);
  return 0;
}

int LLVMFuzzerInitialize(int *argc, char ***argv) { return 0; }
