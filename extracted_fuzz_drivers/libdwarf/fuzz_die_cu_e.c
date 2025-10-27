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
 * A fuzzer that simulates a small part of the simplereader.c example.
 * This fuzzer targets dwarf_init_b.
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
  int fuzz_fd = 0;
  int res = DW_DLV_ERROR;
  Dwarf_Error error = 0;
  Dwarf_Handler errhand = 0;
  Dwarf_Ptr errarg = 0;
  Dwarf_Error *errp = 0;
  int i = 0;

  fuzz_fd = open(filename, O_RDONLY | O_RDONLY);
  if (fuzz_fd != -1) {
    res = dwarf_init_b(fuzz_fd, DW_GROUPNUMBER_ANY, errhand, errarg, &dbg, errp);
    if (res == DW_DLV_OK) {
      Dwarf_Bool is_info = 0;
      Dwarf_Unsigned cu_header_length = 0;
      Dwarf_Half version_stamp = 0;
      Dwarf_Off abbrev_offset = 0;
      Dwarf_Half address_size = 0;
      Dwarf_Half length_size = 0;
      Dwarf_Half extension_size = 0;
      Dwarf_Sig8 type_signature;
      Dwarf_Unsigned typeoffset = 0;
      Dwarf_Unsigned next_cu_header_offset = 0;
      Dwarf_Half header_cu_type = 0;
      Dwarf_Die cu_die = 0;
      static const Dwarf_Sig8 zerosignature;

      type_signature = zerosignature;
      res = dwarf_next_cu_header_e(dbg, is_info, &cu_die, &cu_header_length, &version_stamp, &abbrev_offset, &address_size, &length_size, &extension_size, &type_signature, &typeoffset, &next_cu_header_offset, &header_cu_type, errp);
      if (res == DW_DLV_OK) {
        dwarf_dealloc(dbg, cu_die, DW_DLA_DIE);
      }
    }
  }
  dwarf_finish(dbg);
  close(fuzz_fd);
  unlink(filename);
  return 0;
}
