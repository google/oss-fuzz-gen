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
#include "dwarf.h"
#include "libdwarf.h"
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

int string_offsets_example(Dwarf_Debug dbg, Dwarf_Error *error);
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
  int regtabrulecount = 0;
  int curopt = 0;

  int fd = open(filename, O_RDONLY | O_BINARY);
  if (fd < 0) {
    exit(EXIT_FAILURE);
  }

  res = dwarf_init_b(fd, DW_GROUPNUMBER_ANY, errhand, errarg, &dbg, &error);

  if (res != DW_DLV_OK) {
    dwarf_dealloc_error(dbg, error);
  } else {
    res = string_offsets_example(dbg, &error);
    if (res != DW_DLV_OK) {
    }
  }

  dwarf_finish(dbg);
  close(fd);
  unlink(filename);
  return 0;
}

int string_offsets_example(Dwarf_Debug dbg, Dwarf_Error *error) {
  int res = 0;
  Dwarf_Str_Offsets_Table sot = 0;
  Dwarf_Unsigned wasted_byte_count = 0;
  Dwarf_Unsigned table_count = 0;
  Dwarf_Error closeerror = 0;

  res = dwarf_open_str_offsets_table_access(dbg, &sot, error);
  if (res == DW_DLV_NO_ENTRY) {
    return res;
  }
  if (res == DW_DLV_ERROR) {
    return res;
  }
  for (;;) {
    Dwarf_Unsigned unit_length = 0;
    Dwarf_Unsigned unit_length_offset = 0;
    Dwarf_Unsigned table_start_offset = 0;
    Dwarf_Half entry_size = 0;
    Dwarf_Half version = 0;
    Dwarf_Half padding = 0;
    Dwarf_Unsigned table_value_count = 0;
    Dwarf_Unsigned i = 0;
    Dwarf_Unsigned table_entry_value = 0;

    res = dwarf_next_str_offsets_table(sot, &unit_length, &unit_length_offset, &table_start_offset, &entry_size, &version, &padding, &table_value_count, error);
    if (res == DW_DLV_NO_ENTRY) {
      break;
    }
    if (res == DW_DLV_ERROR) {
      dwarf_close_str_offsets_table_access(sot, &closeerror);
      dwarf_dealloc_error(dbg, closeerror);
      return res;
    }
    for (i = 0; i < table_value_count; ++i) {
      res = dwarf_str_offsets_value_by_index(sot, i, &table_entry_value, error);
      if (res != DW_DLV_OK) {
        dwarf_close_str_offsets_table_access(sot, &closeerror);
        dwarf_dealloc_error(dbg, closeerror);
        return res;
      }
    }
  }
  res = dwarf_str_offsets_statistics(sot, &wasted_byte_count, &table_count, error);
  if (res != DW_DLV_OK) {
    dwarf_close_str_offsets_table_access(sot, &closeerror);
    dwarf_dealloc_error(dbg, closeerror);
    return res;
  }
  res = dwarf_close_str_offsets_table_access(sot, error);
  sot = 0;
  return res;
}
