/*
   Fuzzing ldb_comparison_fold()
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
#include "charset.h"
#include "fuzzing/fuzzing.h"
#include "includes.h"

int LLVMFuzzerInitialize(int *argc, char ***argv) { return 0; }

int LLVMFuzzerTestOneInput(const uint8_t *input, size_t len) {
  struct ldb_val v[3] = {{}, {}, {}};
  size_t i, j, k;
  int results[9], ab, ac, bc;

  if (len < 3) {
    return 0;
  }

  j = 0;
  k = 0;
  v[j].data = discard_const(input);

  /*
   * We split the input into 3 ldb_vals, on the byte '*' (42), chosen
   * because it is *not* special with regard to termination, utf-8, or
   * casefolding.
   *
   * if there are not 2 '*' bytes, the last value[s] will be empty, with
   * a NULL pointer and zero length.
   */

  for (i = 0; i < len; i++) {
    if (input[i] != '*') {
      continue;
    }
    v[j].length = i - k;
    i++;
    j++;
    if (j > 2 || i == len) {
      break;
    }
    k = i;
    v[j].data = discard_const(input + k);
  }

  for (i = 0; i < 3; i++) {
    char *s1 = (char *)v[i].data;
    size_t len1 = v[i].length;
    for (j = 0; j < 3; j++) {
      char *s2 = (char *)v[j].data;
      size_t len2 = v[j].length;
      int r = strncasecmp_ldb(s1, len1, s2, len2);
      if (abs(r) > 1) {
        abort();
      }
      results[i * 3 + j] = r;
    }
  }

  /*
   * There are nine comparisons we make.
   *
   *    A B C
   *  A = x x
   *  B - = x
   *  C - - =
   *
   * The diagonal should be all zeros (A == A, etc)
   * The upper and lower triangles should complement each other
   * (A > B implies B < A; A == B implies B == A).
   *
   * So we check for those identities first.
   */

  if ((results[0] != 0) || (results[4] != 0) || (results[8] != 0)) {
    abort();
  }

  ab = results[3];
  ac = results[6];
  bc = results[7];

  if (ab != -results[1] || ac != -results[2] || bc != -results[5]) {
    abort();
  }

  /*
   * Then there are 27 states within the three comparisons of one
   * triangle, because each of AB, AC, and BC can be in 3 states.
   *
   *  0    (A < B) (A < C) (B < C)   A < B < C
   *  1    (A < B) (A < C) (B = C)   A < (B|C)
   *  2    (A < B) (A < C) (B > C)   A < C < B
   *  3    (A < B) (A = C) (B < C)    invalid
   *  4    (A < B) (A = C) (B = C)    invalid
   *  5    (A < B) (A = C) (B > C)   (A|C) < B
   *  6    (A < B) (A > C) (B < C)    invalid
   *  7    (A < B) (A > C) (B = C)    invalid
   *  8    (A < B) (A > C) (B > C)   C < A < B
   *  9    (A = B) (A < C) (B < C)   (A|B) < C
   * 10    (A = B) (A < C) (B = C)    invalid
   * 11    (A = B) (A < C) (B > C)    invalid
   * 12    (A = B) (A = C) (B < C)    invalid
   * 13    (A = B) (A = C) (B = C)   A = B = C
   * 14    (A = B) (A = C) (B > C)    invalid
   * 15    (A = B) (A > C) (B < C)    invalid
   * 16    (A = B) (A > C) (B = C)    invalid
   * 17    (A = B) (A > C) (B > C)   C < (A|B)
   * 18    (A > B) (A < C) (B < C)   B < C < A
   * 19    (A > B) (A < C) (B = C)    invalid
   * 20    (A > B) (A < C) (B > C)    invalid
   * 21    (A > B) (A = C) (B < C)   B < (A|C)
   * 22    (A > B) (A = C) (B = C)    invalid
   * 23    (A > B) (A = C) (B > C)    invalid
   * 24    (A > B) (A > C) (B < C)   B < C < A
   * 25    (A > B) (A > C) (B = C)   (B|C) < A
   * 26    (A > B) (A > C) (B > C)   C < B < A
   *
   * It actually turns out to be quite simple:
   */

  if (ab == 0) {
    if (ac != bc) {
      abort();
    }
  } else if (ab < 0) {
    if (ac >= 0 && bc <= 0) {
      abort();
    }
  } else {
    if (ac <= 0 && bc >= 0) {
      abort();
    }
  }

  return 0;
}
