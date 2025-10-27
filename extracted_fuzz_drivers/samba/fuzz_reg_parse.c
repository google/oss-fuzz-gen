/*
 * Fuzzing for reg_parse
 * Copyright (C) Michael Hanselmann 2019
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include "fuzzing/fuzzing.h"
#include "includes.h"
#include "lib/util/fault.h"
#include "registry.h"
#include "registry/reg_parse.h"

static FILE *fp;

int LLVMFuzzerInitialize(int *argc, char ***argv) {
  fp = tmpfile();

  return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *buf, size_t len) {
  const reg_parse_callback cb = {0};

  rewind(fp);
  (void)fwrite(buf, len, 1, fp);
  (void)fflush(fp);
  rewind(fp);

  (void)reg_parse_fd(fileno(fp), &cb, "");

  return 0;
}
