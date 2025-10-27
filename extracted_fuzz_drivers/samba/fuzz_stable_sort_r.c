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
#include "util/stable_sort.h"

int LLVMFuzzerInitialize(int *argc, char ***argv) { return 0; }

/*
 * For a "context" we use a byte that the values are XORed with before
 * comparison, for a non-obvious but stable sort order.
 */
static int cmp_int8(int8_t *a, int8_t *b, int8_t *c) { return (*a ^ *c) - (*b ^ *c); }

#define MAX_SIZE (1024 * 1024)

int LLVMFuzzerTestOneInput(const uint8_t *buf, size_t len) {
  size_t i;
  int8_t buf2[MAX_SIZE];
  int8_t aux[MAX_SIZE];
  int8_t context;

  if (len < 1 || len > MAX_SIZE) {
    return 0;
  }
  context = (int8_t)buf[0];
  buf++;
  len--;

  memcpy(buf2, buf, len);

  stable_sort_r(buf2, aux, len, 1, (samba_compare_with_context_fn_t)cmp_int8, &context);

  for (i = 1; i < len; i++) {
    int c = cmp_int8(&buf2[i - 1], &buf2[i], &context);
    if (c > 0) {
      abort();
    }
  }

  return 0;
}
