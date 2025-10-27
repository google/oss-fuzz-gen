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
#include "fuzzing/fuzzing.h"
#include "includes.h"
#include "lib/ldb/include/ldb.h"
#include "lib/ldb/include/ldb_handlers.h"

int LLVMFuzzerInitialize(int *argc, char ***argv) { return 0; }

int LLVMFuzzerTestOneInput(const uint8_t *input, size_t len) {
  struct ldb_val v1, v2;
  struct ldb_context *ldb = NULL;

  if (len < 2) {
    return 0;
  }

  v1.length = PULL_LE_U16(input, 0);
  if (v1.length > len - 2) {
    /* the exact case of v2.length == 0 is still available */
    return 0;
  }
  len -= 2;
  input += 2;

  ldb = ldb_init(NULL, NULL);
  if (ldb == NULL) {
    return 0;
  }

  v1.data = talloc_memdup(ldb, input, v1.length);
  v2.length = len - v1.length;
  v2.data = talloc_memdup(ldb, input + v1.length, v2.length);

  ldb_comparison_fold(ldb, ldb, &v1, &v2);
  talloc_free(ldb);
  return 0;
}
