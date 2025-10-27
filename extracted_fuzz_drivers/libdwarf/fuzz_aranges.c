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
 * Helper function definitions.
 */
static void cleanup_bad_arange(Dwarf_Debug dbg, Dwarf_Arange *arange, Dwarf_Signed i, Dwarf_Signed count);
int arange_processing_example(Dwarf_Debug dbg, Dwarf_Error *error);

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
    printf("Processing");
    arange_processing_example(dbg, &error);
  }

  dwarf_finish(dbg);
  close(fd);
  unlink(filename);
  return 0;
}

static void cleanup_bad_arange(Dwarf_Debug dbg, Dwarf_Arange *arange, Dwarf_Signed i, Dwarf_Signed count) {
  Dwarf_Signed k = i;
  for (; k < count; ++k) {
    dwarf_dealloc(dbg, arange[k], DW_DLA_ARANGE);
    arange[k] = 0;
  }
}

// Source:
// https://www.prevanders.net/libdwarfdoc/group__aranges.html#ga9b628e21a71f4280f93788815796ef92
int arange_processing_example(Dwarf_Debug dbg, Dwarf_Error *error) {
  Dwarf_Signed count = 0;
  Dwarf_Arange *arange = 0;
  int res = 0;

  res = dwarf_get_aranges(dbg, &arange, &count, error);
  if (res == DW_DLV_OK) {
    Dwarf_Signed i = 0;

    for (i = 0; i < count; ++i) {
      Dwarf_Arange ara = arange[i];
      Dwarf_Unsigned segment = 0;
      Dwarf_Unsigned segment_entry_size = 0;
      Dwarf_Addr start = 0;
      Dwarf_Unsigned length = 0;
      Dwarf_Off cu_die_offset = 0;

      res = dwarf_get_arange_info_b(ara, &segment, &segment_entry_size, &start, &length, &cu_die_offset, error);
      if (res != DW_DLV_OK) {
        cleanup_bad_arange(dbg, arange, i, count);
        dwarf_dealloc(dbg, arange, DW_DLA_LIST);
        return res;
      }
      dwarf_dealloc(dbg, ara, DW_DLA_ARANGE);
      arange[i] = 0;
    }
    dwarf_dealloc(dbg, arange, DW_DLA_LIST);
  }
  return res;
}
