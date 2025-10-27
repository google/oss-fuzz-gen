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
#include <sys/types.h>
#include <unistd.h>

#ifndef O_BINARY
#define O_BINARY 0 /* So it does nothing in Linux/Unix */
#endif

/*
 * Libdwarf library callers can only use these headers.
 */
#include "dwarf.h"
#include "libdwarf.h"

/*
 * Fuzzer function
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

  Dwarf_Debug dbg = 0;
  int res = DW_DLV_ERROR;
  Dwarf_Error error = 0;
  Dwarf_Handler errhand = 0;
  Dwarf_Ptr errarg = 0;

  int fd = open(filename, O_RDONLY | O_BINARY);
  if (fd < 0) {
    exit(EXIT_FAILURE);
  }

  res = dwarf_init_b(fd, DW_GROUPNUMBER_ANY, errhand, errarg, &dbg, &error);

  if (res != DW_DLV_OK) {
    dwarf_dealloc_error(dbg, error);
  } else {
    /* libdwarf does not require offset to be anything in
       particular, and will work fine regardless
       (possibly returning DW_DLV_ERROR or DW_DLV_OK).  But
       valgrind generates a warning passing in the uninitialized
       value so let us initialize it to ... something. */
    Dwarf_Off dw_offset = 11;
    char *dw_string;
    Dwarf_Signed dw_strlen_of_string;

    while ((res = dwarf_get_str(dbg, dw_offset, &dw_string, &dw_strlen_of_string, &error)) == DW_DLV_OK) {
      dw_offset += dw_strlen_of_string + 1;
    }
  }

  dwarf_finish(dbg);
  close(fd);
  unlink(filename);
  return 0;
}
