/*
   Fuzzing parse_lpq_entry
   Copyright (C) Douglas Bagnall <dbagnall@samba.org> 2021

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
#include "../../source3/include/includes.h"
#include "fuzzing/fuzzing.h"
#include "printing.h"

int LLVMFuzzerInitialize(int *argc, char ***argv) { return 0; }

#define MAX_LENGTH (1024 * 1024)
char line[MAX_LENGTH + 1];

int LLVMFuzzerTestOneInput(const uint8_t *input, size_t len) {
  enum printing_types printing_type;
  print_queue_struct pq_buf = {0};
  print_status_struct status = {0};
  bool first;
  unsigned x;
  TALLOC_CTX *frame = NULL;

  if (len < 1 || len > MAX_LENGTH) {
    return 0;
  }

  x = input[0];
  input++;
  len--;

  /* There are 14 types, default goes to bsd */
  printing_type = x & 15;
  first = (x & 16) ? true : false;

  memcpy(line, input, len);
  line[len] = '\0';

  /* parse_lpq_bsd requires a stackframe */
  frame = talloc_stackframe();

  parse_lpq_entry(printing_type, line, &pq_buf, /* out */
                  &status,                      /* out */
                  first);
  talloc_free(frame);
  return 0;
}
