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
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define TRUE 1
#define FALSE 0
#ifndef O_BINARY
#define O_BINARY 0
#endif

int examplep5(Dwarf_Die cu_die, Dwarf_Error *error);

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
  Dwarf_Sig8 hash8;
  Dwarf_Error *errp = 0;
  int simpleerrhand = 0;
  int i = 0;
  Dwarf_Die die;

  fuzz_fd = open(filename, O_RDONLY | O_BINARY);
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
      int res = 0;
      Dwarf_Die cu_die = 0;
      int level = 0;
      static const Dwarf_Sig8 zerosignature;

      type_signature = zerosignature;
      res = dwarf_next_cu_header_d(dbg, is_info, &cu_header_length, &version_stamp, &abbrev_offset, &address_size, &length_size, &extension_size, &type_signature, &typeoffset, &next_cu_header_offset, &header_cu_type, errp);
      if (res == DW_DLV_OK) {
        printf(">>CU header length..........0x%lx\n", (unsigned long)cu_header_length);
        printf(">>Version stamp.............%d\n", version_stamp);
        printf(">>Address size .............%d\n", address_size);
        printf(">>Offset size...............%d\n", length_size);
        printf(">>Next cu header offset.....0x%lx\n", (unsigned long)next_cu_header_offset);
        res = dwarf_siblingof_b(dbg, NULL, is_info, &cu_die, errp);
        if (res == DW_DLV_OK) {
          examplep5(cu_die, &error);
        };
        dwarf_dealloc(dbg, cu_die, DW_DLA_DIE);
      }
    }
  }
  dwarf_finish(dbg);
  close(fuzz_fd);
  unlink(filename);
  return 0;
}

int examplep5(Dwarf_Die cu_die, Dwarf_Error *error) {
  int lres = 0;
  Dwarf_Unsigned version = 0;
  Dwarf_Macro_Context macro_context = 0;
  Dwarf_Unsigned macro_unit_offset = 0;
  Dwarf_Unsigned number_of_ops = 0;
  Dwarf_Unsigned ops_total_byte_len = 0;
  Dwarf_Bool is_primary = TRUE;
  unsigned k = 0;

  /*  Just call once each way to test both.
      Really the second is just for imported units,
      but this is a  way to get testing of both calls.
  */
  for (; k < 2; ++k) {
    if (is_primary) {
      lres = dwarf_get_macro_context(cu_die, &version, &macro_context, &macro_unit_offset, &number_of_ops, &ops_total_byte_len, error);
      is_primary = FALSE;
    } else {
      lres = dwarf_get_macro_context_by_offset(cu_die, macro_unit_offset, &version, &macro_context, &number_of_ops, &ops_total_byte_len, error);
    }

    if (lres == DW_DLV_ERROR) {
      return lres;
    }
    if (lres == DW_DLV_NO_ENTRY) {
      break;
    }
    for (k = 0; k < number_of_ops; ++k) {
      Dwarf_Unsigned section_offset = 0;
      Dwarf_Half macro_operator = 0;
      Dwarf_Half forms_count = 0;
      const Dwarf_Small *formcode_array = 0;
      Dwarf_Unsigned line_number = 0;
      Dwarf_Unsigned index = 0;
      Dwarf_Unsigned offset = 0;
      const char *macro_string = 0;
      int lres2 = 0;

      lres2 = dwarf_get_macro_op(macro_context, k, &section_offset, &macro_operator, &forms_count, &formcode_array, error);
      if (lres2 != DW_DLV_OK) {
        dwarf_dealloc_macro_context(macro_context);
        return lres2;
      }
      switch (macro_operator) {
      case 0:
        break;
      case DW_MACRO_end_file:
        break;
      case DW_MACRO_define:
      case DW_MACRO_undef:
      case DW_MACRO_define_strp:
      case DW_MACRO_undef_strp:
      case DW_MACRO_define_strx:
      case DW_MACRO_undef_strx:
      case DW_MACRO_define_sup:
      case DW_MACRO_undef_sup: {
        lres2 = dwarf_get_macro_defundef(macro_context, k, &line_number, &index, &offset, &forms_count, &macro_string, error);
        if (lres2 != DW_DLV_OK) {
          dwarf_dealloc_macro_context(macro_context);
          return lres2;
        }
      } break;
      case DW_MACRO_start_file: {
        lres2 = dwarf_get_macro_startend_file(macro_context, k, &line_number, &index, &macro_string, error);
        if (lres2 != DW_DLV_OK) {
          dwarf_dealloc_macro_context(macro_context);
          return lres2;
        }
      } break;
      case DW_MACRO_import: {
        lres2 = dwarf_get_macro_import(macro_context, k, &offset, error);
        if (lres2 != DW_DLV_OK) {
          dwarf_dealloc_macro_context(macro_context);
          return lres2;
        }
      } break;
      case DW_MACRO_import_sup: {
        lres2 = dwarf_get_macro_import(macro_context, k, &offset, error);
        if (lres2 != DW_DLV_OK) {
          dwarf_dealloc_macro_context(macro_context);
          return lres2;
        }
      } break;
      default:
        break;
      }
    }
    dwarf_dealloc_macro_context(macro_context);
    macro_context = 0;
  }
  return DW_DLV_OK;
}
