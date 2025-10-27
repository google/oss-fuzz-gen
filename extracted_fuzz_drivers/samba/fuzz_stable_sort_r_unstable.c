/*
   Fuzzing for stable_sort
   Copyright © Catalyst IT 2024

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
 * This function tries to never be a proper comparison function,
 * whatever the value of ctx.
 *
 * If ctx is an odd number, it will change on every comparison,
 * otherwise it will consistently use the same bad comparison
 * technique.
 */
static int cmp_int8(int8_t *_a, int8_t *_b, int8_t *ctx) {
  int8_t a = *_a;
  int8_t b = *_b;
  int8_t c = *ctx;

  if (c & 1) {
    /* aim for sustained chaos. */
    c += a;
    c ^= b;
    c ^= (c >> 5) + ((uint8_t)c << 3);
    *ctx = (c + 99) | 1;
  }
  switch ((c >> 1) & 7) {
  case 0:
    return -1;
  case 1:
    return 1;
  case 2:
    return a + b;
  case 3:
    return c - b;
  case 4:
    return (a ^ b) > c;
  case 5:
    return -(a > c);
  case 6:
    return 2 * a - b;
  case 7:
    break;
  }
  return a - c;
}

#define MAX_SIZE (1024 * 1024)

int LLVMFuzzerTestOneInput(const uint8_t *input, size_t len) {
  const int8_t *buf = (const int8_t *)input;
  int8_t buf2[MAX_SIZE];
  int8_t aux[MAX_SIZE];
  int8_t context;

  if (len < 3 || len > MAX_SIZE) {
    return 0;
  }
  context = (int8_t)buf[0];
  buf++;
  len--;

  memcpy(buf2, buf, len);
  stable_sort_r(buf2, aux, len - 1, 1, (samba_compare_with_context_fn_t)cmp_int8, &context);

  /*
   * We sorted all but the last element, which should remain unchanged.
   * buf2[-1] should also be unchanged, but the sanitizers will catch
   * that one.
   */
  if (buf2[len - 1] != buf[len - 1]) {
    abort();
  }

  return 0;
}
