/*
 * Unix SMB/CIFS implementation.
 * Windows NT registry I/O library
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
#include "registry/reg_objects.h"
#include "registry/regfio.h"
#include "system/filesys.h"

static FILE *fp;
static char filename[128];

int LLVMFuzzerInitialize(int *argc, char ***argv) {
  fp = tmpfile();

  (void)snprintf(filename, sizeof(filename), "/proc/self/fd/%d", fileno(fp));

  return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *buf, size_t len) {
  REGF_FILE *regfile;
  REGF_NK_REC *nk, *subkey;

  rewind(fp);
  (void)fwrite(buf, len, 1, fp);
  (void)fflush(fp);

  regfile = regfio_open(filename, O_RDONLY, 0600);
  if (!regfile) {
    goto out;
  }

  regfile->ignore_checksums = true;

  nk = regfio_rootkey(regfile);
  if (nk != NULL) {
    nk->subkey_index = 0;
    while ((subkey = regfio_fetch_subkey(regfile, nk))) {
    }
  }

out:
  if (regfile != NULL) {
    regfio_close(regfile);
  }

  return 0;
}
