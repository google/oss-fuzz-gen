/* Copyright 2021 Google LLC
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
      http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
#include <fcntl.h> /* open() O_RDONLY O_BINARY */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

/*
 * Libdwarf library callers can only use these headers.
 */
#include "dwarf.h"
#include "libdwarf.h"
#ifndef O_BINARY
#define O_BINARY 0
#endif

/*
 * Fuzzer function targeting dwarf_crc32
 */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  char filename[256];
  sprintf(filename, "/tmp/libfuzzer.%d", getpid());

  FILE *fp = fopen(filename, "wb");
  if (!fp) {
    return 0;
  }
  fwrite(data, size, 1, fp);
  fclose(fp);

  int fuzz_fd = 0;
  Dwarf_Ptr errarg = 0;
  Dwarf_Handler errhand = 0;
  Dwarf_Error error = 0;
  Dwarf_Debug dbg = 0;
  off_t size_left = 0;
  off_t fsize = 0;
  unsigned char *crcbuf = 0;
  int res = 0;

  fuzz_fd = open(filename, O_RDONLY | O_BINARY);
  fsize = size_left = lseek(fuzz_fd, 0L, SEEK_END);
  /*  The read below will fail, so to avoid
      reading uninitialized data we ensure
      the data is initialized. */

  if (fuzz_fd != -1) {
    dwarf_init_b(fuzz_fd, DW_GROUPNUMBER_ANY, errhand, errarg, &dbg, &error);
    /*  By not checking the return code, on a failed init
        we cannot dealloc the error field, so
        there is a leak from
        _dwarf_special_no_dbg_error_malloc()  */
    /*  The library has no way to verify a non-null
        crcbuf points to a valid 4 byte block of memory.
        Passing in NULL results in returning DW_DLV_NO_ENTRY. */
    res = dwarf_crc32(dbg, crcbuf, &error);
    /*  Ignoring res! */

    dwarf_finish(dbg);
  }
  close(fuzz_fd);
  unlink(filename);
  return 0;
}
