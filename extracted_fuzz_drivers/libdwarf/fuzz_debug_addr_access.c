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

  int fuzz_fd = 0;
  Dwarf_Ptr errarg = 0;
  Dwarf_Handler errhand = 0;
  Dwarf_Error *errp = 0;
  Dwarf_Debug dbg = 0;

  fuzz_fd = open(filename, O_RDONLY | O_BINARY);
  if (fuzz_fd != -1) {
    int res = dwarf_init_b(fuzz_fd, DW_GROUPNUMBER_ANY, errhand, errarg, &dbg, errp);

    if (res != DW_DLV_OK) {
      dwarf_finish(dbg);
      close(fuzz_fd);
      unlink(filename);
      return 0;
    }
    Dwarf_Debug_Addr_Table debug_address_table;
    Dwarf_Unsigned dw_section_offset = 0;
    Dwarf_Unsigned dw_debug_address_table_length = 0;
    Dwarf_Half dw_version;
    Dwarf_Small dw_address_size;
    Dwarf_Unsigned dw_dw_at_addr_base;
    Dwarf_Unsigned dw_entry_count;
    Dwarf_Unsigned dw_next_table_offset;
    res = dwarf_debug_addr_table(dbg, dw_section_offset, &debug_address_table, &dw_debug_address_table_length, &dw_version, &dw_address_size, &dw_dw_at_addr_base, &dw_entry_count, &dw_next_table_offset, errp);

    if (res != DW_DLV_OK) {
      if (res == DW_DLV_ERROR) {
        if (errp) {
          dwarf_dealloc_error(dbg, *errp);
        }
      }
      dwarf_finish(dbg);
      close(fuzz_fd);
      unlink(filename);
      return 0;
    }
    for (Dwarf_Unsigned curindex = 0; curindex < dw_entry_count; ++curindex) {
      Dwarf_Unsigned addr = 0;
      res = dwarf_debug_addr_by_index(debug_address_table, curindex, &addr, errp);

      if (res != DW_DLV_OK) {
        break;
      }
    }
    if (errp) {
      dwarf_dealloc_error(dbg, *errp);
    }
    dwarf_dealloc_debug_addr_table(debug_address_table);
    dwarf_finish(dbg);
    close(fuzz_fd);
  }

  unlink(filename);
  return 0;
}
