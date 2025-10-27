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

int examplew(Dwarf_Debug dbg, Dwarf_Error *error);
int examplewgdbindex(Dwarf_Gdbindex gdbindex, Dwarf_Error *error);
int examplex(Dwarf_Gdbindex gdbindex, Dwarf_Error *error);

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
    examplew(dbg, &error);
  }

  dwarf_finish(dbg);
  close(fd);
  unlink(filename);
  return 0;
}

int examplew(Dwarf_Debug dbg, Dwarf_Error *error) {
  Dwarf_Gdbindex gindexptr = 0;
  Dwarf_Unsigned version = 0;
  Dwarf_Unsigned cu_list_offset = 0;
  Dwarf_Unsigned types_cu_list_offset = 0;
  Dwarf_Unsigned address_area_offset = 0;
  Dwarf_Unsigned symbol_table_offset = 0;
  Dwarf_Unsigned constant_pool_offset = 0;
  Dwarf_Unsigned section_size = 0;
  const char *section_name = 0;
  int res = 0;

  res = dwarf_gdbindex_header(dbg, &gindexptr, &version, &cu_list_offset, &types_cu_list_offset, &address_area_offset, &symbol_table_offset, &constant_pool_offset, &section_size, &section_name, error);
  if (res != DW_DLV_OK) {
    return res;
  }
  {
    Dwarf_Unsigned length = 0;
    Dwarf_Unsigned typeslength = 0;
    Dwarf_Unsigned i = 0;
    res = dwarf_gdbindex_culist_array(gindexptr, &length, error);
    if (res != DW_DLV_OK) {
      dwarf_dealloc_gdbindex(gindexptr);
      return res;
    }
    for (i = 0; i < length; ++i) {
      Dwarf_Unsigned cuoffset = 0;
      Dwarf_Unsigned culength = 0;
      res = dwarf_gdbindex_culist_entry(gindexptr, i, &cuoffset, &culength, error);
      if (res != DW_DLV_OK) {
        return res;
      }
    }
    res = dwarf_gdbindex_types_culist_array(gindexptr, &typeslength, error);
    if (res != DW_DLV_OK) {
      dwarf_dealloc_gdbindex(gindexptr);
      return res;
    }
    for (i = 0; i < typeslength; ++i) {
      Dwarf_Unsigned cuoffset = 0;
      Dwarf_Unsigned tuoffset = 0;
      Dwarf_Unsigned type_signature = 0;
      res = dwarf_gdbindex_types_culist_entry(gindexptr, i, &cuoffset, &tuoffset, &type_signature, error);
      if (res != DW_DLV_OK) {
        dwarf_dealloc_gdbindex(gindexptr);
        return res;
      }
    }

    res = examplewgdbindex(gindexptr, error);
    if (res != DW_DLV_OK) {
      dwarf_dealloc_gdbindex(gindexptr);
      return res;
    }

    res = examplex(gindexptr, error);
    if (res != DW_DLV_OK) {
      dwarf_dealloc_gdbindex(gindexptr);
      return res;
    }

    dwarf_dealloc_gdbindex(gindexptr);
  }
  return DW_DLV_OK;
}

int examplewgdbindex(Dwarf_Gdbindex gdbindex, Dwarf_Error *error) {
  Dwarf_Unsigned list_len = 0;
  Dwarf_Unsigned i = 0;
  int res = 0;

  res = dwarf_gdbindex_addressarea(gdbindex, &list_len, error);
  if (res != DW_DLV_OK) {
    return res;
  }
  for (i = 0; i < list_len; i++) {
    Dwarf_Unsigned lowpc = 0;
    Dwarf_Unsigned highpc = 0;
    Dwarf_Unsigned cu_index = 0;
    res = dwarf_gdbindex_addressarea_entry(gdbindex, i, &lowpc, &highpc, &cu_index, error);
    if (res != DW_DLV_OK) {
      return res;
    }
  }
  return DW_DLV_OK;
}

int examplex(Dwarf_Gdbindex gdbindex, Dwarf_Error *error) {
  Dwarf_Unsigned symtab_list_length = 0;
  Dwarf_Unsigned i = 0;
  int res = 0;

  res = dwarf_gdbindex_symboltable_array(gdbindex, &symtab_list_length, error);
  if (res != DW_DLV_OK) {
    return res;
  }
  for (i = 0; i < symtab_list_length; i++) {
    Dwarf_Unsigned symnameoffset = 0;
    Dwarf_Unsigned cuvecoffset = 0;
    Dwarf_Unsigned cuvec_len = 0;
    Dwarf_Unsigned ii = 0;
    const char *name = 0;
    int resl = 0;

    resl = dwarf_gdbindex_symboltable_entry(gdbindex, i, &symnameoffset, &cuvecoffset, error);
    if (resl != DW_DLV_OK) {
      return resl;
    }
    resl = dwarf_gdbindex_string_by_offset(gdbindex, symnameoffset, &name, error);
    if (resl != DW_DLV_OK) {
      return resl;
    }
    resl = dwarf_gdbindex_cuvector_length(gdbindex, cuvecoffset, &cuvec_len, error);
    if (resl != DW_DLV_OK) {
      return resl;
    }
    for (ii = 0; ii < cuvec_len; ++ii) {
      Dwarf_Unsigned attributes = 0;
      Dwarf_Unsigned cu_index = 0;
      Dwarf_Unsigned symbol_kind = 0;
      Dwarf_Unsigned is_static = 0;
      int res2 = 0;

      res2 = dwarf_gdbindex_cuvector_inner_attributes(gdbindex, cuvecoffset, ii, &attributes, error);
      if (res2 != DW_DLV_OK) {
        return res2;
      }
      res2 = dwarf_gdbindex_cuvector_instance_expand_value(gdbindex, attributes, &cu_index, &symbol_kind, &is_static, error);
      if (res2 != DW_DLV_OK) {
        return res2;
      }
    }
  }
  return DW_DLV_OK;
}
