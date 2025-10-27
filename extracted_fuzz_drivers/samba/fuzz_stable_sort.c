/*
   Fuzzing for stable_sort
   Copyright © Catalyst IT

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
#include "talloc.h"
#include "util/stable_sort.h"

int LLVMFuzzerInitialize(int *argc, char ***argv) { return 0; }

#define CMP_FN(type)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   \
  static int cmp_##type(type *a, type *b) {                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            \
    if (*a > *b) {                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     \
      return 1;                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        \
    }                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  \
    if (*a < *b) {                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     \
      return -1;                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       \
    }                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  \
    return 0;                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          \
  }

CMP_FN(uint8_t)
CMP_FN(uint16_t)
CMP_FN(uint32_t)
CMP_FN(uint64_t)

#define MAX_SIZE (1024 * 1024)

int LLVMFuzzerTestOneInput(const uint8_t *buf, size_t len) {
  TALLOC_CTX *mem_ctx = NULL;
  samba_compare_fn_t fn;
  size_t s, i;
  uint8_t buf2[MAX_SIZE];

  if (len < 1 || len > MAX_SIZE) {
    return 0;
  }
  s = 1 << (buf[0] & 3);
  if (s == 1) {
    fn = (samba_compare_fn_t)cmp_uint8_t;
  } else if (s == 2) {
    fn = (samba_compare_fn_t)cmp_uint16_t;
  } else if (s == 4) {
    fn = (samba_compare_fn_t)cmp_uint32_t;
  } else {
    fn = (samba_compare_fn_t)cmp_uint64_t;
  }
  buf++;
  len--;
  len -= len & (s - 1);

  mem_ctx = talloc_new(NULL);
  memcpy(buf2, buf, len);

  stable_sort_talloc(mem_ctx, buf2, len / s, s, fn);

  talloc_free(mem_ctx);

  for (i = s; i < len; i += s) {
    int c = fn(&buf2[i - s], &buf2[i]);
    if (c > 0) {
      abort();
    }
  }

  return 0;
}
