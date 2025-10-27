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

/*  This now initializes local variables to zero
    rather than leaving them uninitialized.
    When uninitialized consistent behavior is
    unlikely, run-to-run.  And
    crashes are likely.
    David Anderson 30 May 2023.
*/
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

    Dwarf_Dnames_Head dnames_h = 0;
    Dwarf_Off dw_offset_of_next_table = 0;
    res = dwarf_dnames_header(dbg, 0, &dnames_h, &dw_offset_of_next_table, &error);

    if (res != DW_DLV_OK) {
      dwarf_dealloc_dnames(dnames_h);
      dwarf_finish(dbg);
      close(fd);
      unlink(filename);
      return 0;
    }

    Dwarf_Unsigned dw_index = 1;
    Dwarf_Unsigned dw_abbrev_offset = 0;
    Dwarf_Unsigned dw_abbrev_code = 0;
    Dwarf_Unsigned dw_abbrev_tag = 0;
    Dwarf_Unsigned dw_array_size = 256;
    /*  This test code originally passed in uninitialized
        pointers dw_idxattr_array and dw_form_array, which
        we cannot protect against. But we can check for NULL
        so now the variables are initialilized.
        In any case this code does not call the function correctly,
        but we leave that as written. David Anderson 30 May 2023 */
    Dwarf_Half *dw_idxattr_array = 0;
    Dwarf_Half *dw_form_array = 0;
    Dwarf_Unsigned dw_idxattr_count = 0;

    res = dwarf_dnames_abbrevtable(dnames_h, dw_index, &dw_abbrev_offset, &dw_abbrev_code, &dw_abbrev_tag, dw_array_size, dw_idxattr_array, dw_form_array, &dw_idxattr_count);
    if (res == DW_DLV_NO_ENTRY) {
    }

    Dwarf_Unsigned dw_comp_unit_count = 0;
    Dwarf_Unsigned dw_local_type_unit_count = 0;
    Dwarf_Unsigned dw_foreign_type_unit_count = 0;
    Dwarf_Unsigned dw_bucket_count = 0;
    Dwarf_Unsigned dw_name_count = 0;
    Dwarf_Unsigned dw_abbrev_table_size = 0;
    Dwarf_Unsigned dw_entry_pool_size = 0;
    Dwarf_Unsigned dw_augmentation_string_size = 0;
    char *dw_augmentation_string = 0;
    Dwarf_Unsigned dw_section_size = 0;
    Dwarf_Half dw_table_version = 0;
    Dwarf_Half dw_offset_size = 0;
    res = dwarf_dnames_sizes(dnames_h, &dw_comp_unit_count, &dw_local_type_unit_count, &dw_foreign_type_unit_count, &dw_bucket_count, &dw_name_count, &dw_abbrev_table_size, &dw_entry_pool_size, &dw_augmentation_string_size, &dw_augmentation_string, &dw_section_size, &dw_table_version, &dw_offset_size, &error);
    if (res != DW_DLV_OK) {
      dwarf_dealloc_dnames(dnames_h);
      dwarf_finish(dbg);
      close(fd);
      unlink(filename);
      return 0;
    }

    Dwarf_Unsigned dw_header_offset = 0;
    Dwarf_Unsigned dw_cu_table_offset = 0;
    Dwarf_Unsigned dw_tu_local_offset = 0;
    Dwarf_Unsigned dw_foreign_tu_offset = 0;
    Dwarf_Unsigned dw_bucket_offset = 0;
    Dwarf_Unsigned dw_hashes_offset = 0;
    Dwarf_Unsigned dw_stringoffsets_offset = 0;
    Dwarf_Unsigned dw_entryoffsets_offset = 0;
    Dwarf_Unsigned dw_abbrev_table_offset = 0;
    Dwarf_Unsigned dw_entry_pool_offset = 0;
    res = dwarf_dnames_offsets(dnames_h, &dw_header_offset, &dw_cu_table_offset, &dw_tu_local_offset, &dw_foreign_tu_offset, &dw_bucket_offset, &dw_hashes_offset, &dw_stringoffsets_offset, &dw_entryoffsets_offset, &dw_abbrev_table_offset, &dw_entry_pool_offset, &error);
    if (res != DW_DLV_OK) {
      dwarf_dealloc_dnames(dnames_h);
      dwarf_finish(dbg);
      close(fd);
      unlink(filename);
      return 0;
    }

    Dwarf_Unsigned dw_offset = 0;
    Dwarf_Sig8 dw_sig;
    res = dwarf_dnames_cu_table(dnames_h, "cu", 0, &dw_offset, &dw_sig, &error);
    if (res != DW_DLV_OK) {
      dwarf_dealloc_dnames(dnames_h);
      dwarf_finish(dbg);
      close(fd);
      unlink(filename);
      return 0;
    }

    dw_index = 0;
    Dwarf_Unsigned dw_indexcount;
    res = dwarf_dnames_bucket(dnames_h, 0, &dw_index, &dw_indexcount, &error);
    if (res != DW_DLV_OK) {
      dwarf_dealloc_dnames(dnames_h);
      dwarf_finish(dbg);
      close(fd);
      unlink(filename);
      return 0;
    }

    Dwarf_Unsigned dw_bucket_number = 0;
    Dwarf_Unsigned dw_hash_value = 0;
    Dwarf_Unsigned dw_offset_to_debug_str = 0;
    char *dw_ptrtostr = 0;
    Dwarf_Unsigned dw_offset_in_entrypool = 0;
    Dwarf_Unsigned dw_abbrev_number = 0;
    Dwarf_Half abbrev_tg = 0;
    dw_array_size = 10;
    Dwarf_Half idxattr_array[10];
    Dwarf_Half form_array[10];
    res = dwarf_dnames_name(dnames_h, 1, &dw_bucket_number, &dw_hash_value, &dw_offset_to_debug_str, &dw_ptrtostr, &dw_offset_in_entrypool, &dw_abbrev_number, &abbrev_tg, dw_array_size, idxattr_array, form_array, &dw_idxattr_count, &error);
    if (res != DW_DLV_OK) {
      dwarf_dealloc_dnames(dnames_h);
      dwarf_finish(dbg);
      close(fd);
      unlink(filename);
      return 0;
    }

    dwarf_dealloc_dnames(dnames_h);
  }

  dwarf_finish(dbg);
  close(fd);
  unlink(filename);
  return 0;
}
