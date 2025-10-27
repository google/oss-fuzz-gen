/*
   Fuzzing ldb_parse_control_from_string
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
  struct ldb_control *control = NULL;
  struct ldb_context *ldb = ldb_init(NULL, NULL);
  if (ldb == NULL) {
    return 0;
  }
  /*
   * We copy the buffer in order to NUL-terminate, because running off
   *  the end of the string would be an uninteresting crash.
   */
  if (len > MAX_LENGTH) {
    len = MAX_LENGTH;
  }
  memcpy(buf, input, len);
  buf[len] = 0;

  control = ldb_parse_control_from_string(ldb, ldb, buf);
  if (control != NULL) {
    ldb_control_to_string(ldb, control);
  }
  TALLOC_FREE(ldb);
  return 0;
}

int LLVMFuzzerInitialize(int *argc, char ***argv) { return 0; }
