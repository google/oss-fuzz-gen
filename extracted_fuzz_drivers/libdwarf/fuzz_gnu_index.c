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
 * A fuzzer that simulates a small part of the simplereader.c example.
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
    if (res == DW_DLV_ERROR) {
    }
    dwarf_dealloc_error(dbg, error);
  } else {
    Dwarf_Bool dw_which_section = 0;
    Dwarf_Gnu_Index_Head dw_head;
    Dwarf_Unsigned dw_index_block_count;

    res = dwarf_get_gnu_index_head(dbg, dw_which_section, &dw_head, &dw_index_block_count, &error);

    if (res == DW_DLV_NO_ENTRY) {
    } else if (res == DW_DLV_ERROR) {
      dwarf_dealloc_error(dbg, error);
    } else {
      Dwarf_Unsigned dw_block_length;
      Dwarf_Half dw_version;
      Dwarf_Unsigned dw_offset_into_debug_info;
      Dwarf_Unsigned dw_size_of_debug_info_area;
      Dwarf_Unsigned dw_count_of_index_entries;
      for (Dwarf_Unsigned block_number = 0; block_number < dw_index_block_count; block_number++) {
        res = dwarf_get_gnu_index_block(dw_head, block_number, &dw_block_length, &dw_version, &dw_offset_into_debug_info, &dw_size_of_debug_info_area, &dw_count_of_index_entries, &error);

        if (res == DW_DLV_NO_ENTRY) {
          continue;
        } else if (res == DW_DLV_ERROR) {
          break;
        }
        for (Dwarf_Unsigned entry_number = 0; entry_number < dw_count_of_index_entries; entry_number++) {
          Dwarf_Unsigned dw_offset_in_debug_info;
          const char *dw_name_string;
          unsigned char dw_flagbyte;
          unsigned char dw_staticorglobal;
          unsigned char dw_typeofentry;
          res = dwarf_get_gnu_index_block_entry(dw_head, block_number, entry_number, &dw_offset_in_debug_info, &dw_name_string, &dw_flagbyte, &dw_staticorglobal, &dw_typeofentry, &error);
        }
      }
      dwarf_gnu_index_dealloc(dw_head);
    }
  }

  dwarf_finish(dbg);
  close(fd);
  unlink(filename);
  return 0;
}
