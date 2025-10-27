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

int get_pubtypes_example(Dwarf_Debug dbg, Dwarf_Error *error);
int get_globals_by_type_example(Dwarf_Debug dbg, Dwarf_Error *error);
int get_globals_example(Dwarf_Debug dbg, Dwarf_Error *error);

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
    dwarf_dealloc_error(dbg, error);
  } else {
    dwarf_return_empty_pubnames(dbg, 1);
    dwarf_return_empty_pubnames(dbg, 0);
    get_globals_example(dbg, &error);
    get_globals_by_type_example(dbg, &error);
  }

  dwarf_finish(dbg);
  close(fd);
  unlink(filename);
  return 0;
}

int get_globals_example(Dwarf_Debug dbg, Dwarf_Error *error) {
  Dwarf_Signed count = 0;
  Dwarf_Global *globs = 0;
  Dwarf_Signed i = 0;
  int res = 0;

  res = dwarf_get_globals(dbg, &globs, &count, error);
  if (res != DW_DLV_OK) {
    return res;
  }
  for (i = 0; i < count; ++i) {
    int tag_idx = dwarf_global_tag_number(globs[i]); // DWARF5 only

    char *name = 0;
    res = dwarf_globname(globs[i], &name, error);
    if (res != DW_DLV_OK) {
      continue;
    }

    Dwarf_Off dw_die_offset;
    res = dwarf_global_die_offset(globs[i], &dw_die_offset, error);
    if (res != DW_DLV_OK) {
      continue;
    }
    Dwarf_Off dw_cu_offset;
    res = dwarf_global_cu_offset(globs[i], &dw_cu_offset, error);
    if (res != DW_DLV_OK) {
      continue;
    }

    char *name_2;
    Dwarf_Off dw_die_offset_2, dw_cu_offset_2;
    dwarf_global_name_offsets(globs[i], &name_2, &dw_die_offset_2, &dw_cu_offset_2, error);
    if (res != DW_DLV_OK) {
      continue;
    }

    int dw_category;
    Dwarf_Off dw_offset_pub_header;
    Dwarf_Unsigned dw_length_size;
    Dwarf_Unsigned dw_length_pub;
    Dwarf_Unsigned dw_version;
    Dwarf_Unsigned dw_header_info_offset;
    Dwarf_Unsigned dw_info_length;
    res = dwarf_get_globals_header(globs[i], &dw_category, &dw_offset_pub_header, &dw_length_size, &dw_length_pub, &dw_version, &dw_header_info_offset, &dw_info_length, error);
  }
  dwarf_globals_dealloc(dbg, globs, count);
  return DW_DLV_OK;
}

/* DWARF4 */
int get_globals_by_type_example(Dwarf_Debug dbg, Dwarf_Error *error) {
  int res = DW_DLV_OK;
  for (int i = 0; i < 6; i++) {
    Dwarf_Signed count = 0;
    Dwarf_Global *contents = 0;
    Dwarf_Signed i = 0;

    res = dwarf_globals_by_type(dbg, i, &contents, &count, error);

    dwarf_globals_dealloc(dbg, contents, count);
  }

  return res;
}

/* DWARF4 */
int get_pubtypes_example(Dwarf_Debug dbg, Dwarf_Error *error) {
  Dwarf_Signed count = 0;
  Dwarf_Global *contents = 0;

  int res = dwarf_get_pubtypes(dbg, &contents, &count, error);

  dwarf_globals_dealloc(dbg, contents, count);

  return res;
}
