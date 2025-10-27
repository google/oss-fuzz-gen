/*
   Fuzzing for oLschema2ldif
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
#include "utils/oLschema2ldif/lib.h"

static FILE *devnull;

int LLVMFuzzerInitialize(int *argc, char ***argv) {
  devnull = fopen("/dev/null", "w");

  return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *buf, size_t len) {
  TALLOC_CTX *mem_ctx;
  struct conv_options opt;

  if (len == 0) {
    /*
     * Otherwise fmemopen() will return null and set errno
     * to EINVAL
     */
    return 0;
  }

  mem_ctx = talloc_init(__FUNCTION__);
  if (mem_ctx == NULL) {
    return 0;
  }

  opt.in = fmemopen(buf, len, "r");
  opt.out = devnull;
  opt.ldb_ctx = ldb_init(mem_ctx, NULL);
  if (opt.ldb_ctx == NULL || opt.in == NULL) {
    talloc_free(mem_ctx);
    return 0;
  }

  opt.basedn = ldb_dn_new(mem_ctx, opt.ldb_ctx, "");
  if (opt.basedn == NULL) {
    talloc_free(mem_ctx);
    return 0;
  }

  process_file(mem_ctx, &opt);

  fclose(opt.in);

  talloc_free(mem_ctx);

  return 0;
}
