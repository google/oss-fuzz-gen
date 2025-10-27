/*
   Fuzzing for trivial smb.conf parsing code.
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

#include "fuzzing.h"
#include "includes.h"
#include "lib/util/tiniparser.h"

int LLVMFuzzerInitialize(int *argc, char ***argv) { return 0; }

int LLVMFuzzerTestOneInput(const uint8_t *buf, size_t len) {
  FILE *fp = NULL;
  struct tiniparser_dictionary *d = NULL;

  if (len == 0) {
    /*
     * Otherwise fmemopen() will return null and set errno
     * to EINVAL
     */
    return 0;
  }

  fp = fmemopen(buf, len, "r");

  d = tiniparser_load_stream(fp);
  if (d != NULL) {
    tiniparser_freedict(d);
  }

  fclose(fp);

  return 0;
}
