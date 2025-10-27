/*
   Fuzzing ldb_ldif_read_string
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

int LLVMFuzzerTestOneInput(const uint8_t *input, size_t len) {
  struct ldb_ldif *ldif = NULL;
  const char *s = NULL;
  struct ldb_context *ldb = ldb_init(NULL, NULL);
  if (ldb == NULL) {
    return 0;
  }

  if (len > MAX_LENGTH) {
    len = MAX_LENGTH;
  }
  memcpy(buf, input, len);
  buf[len] = 0;
  s = buf;

  ldif = ldb_ldif_read_string(ldb, &s);

  if (ldif != NULL) {
    ldb_ldif_write_string(ldb, ldb, ldif);
    ldb_ldif_write_redacted_trace_string(ldb, ldb, ldif);
  }
  TALLOC_FREE(ldb);
  return 0;
}

int LLVMFuzzerInitialize(int *argc, char ***argv) { return 0; }
