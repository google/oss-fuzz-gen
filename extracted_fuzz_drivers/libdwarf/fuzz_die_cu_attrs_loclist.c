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

  Dwarf_Debug dbg = 0;
  int fuzz_fd = 0;
  int res = DW_DLV_ERROR;
  Dwarf_Error error = 0;
  Dwarf_Handler errhand = 0;
  Dwarf_Ptr errarg = 0;
  Dwarf_Error *errp = 0;
  int i = 0;
  Dwarf_Die die = 0;

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
      Dwarf_Die cu_die = 0;
      static const Dwarf_Sig8 zerosignature;

      type_signature = zerosignature;
      res = dwarf_next_cu_header_d(dbg, is_info, &cu_header_length, &version_stamp, &abbrev_offset, &address_size, &length_size, &extension_size, &type_signature, &typeoffset, &next_cu_header_offset, &header_cu_type, errp);
      if (res == DW_DLV_OK) {
        res = dwarf_siblingof_b(dbg, NULL, is_info, &cu_die, errp);
        if (res == DW_DLV_OK) {
          Dwarf_Attribute *atlist = 0;
          Dwarf_Signed atcount = 0;
          Dwarf_Attribute attr = 0;

          res = dwarf_attr(cu_die, DW_AT_name, &attr, errp);
          res = dwarf_attrlist(cu_die, &atlist, &atcount, &error);

          Dwarf_Loc_Head_c loclisthead = 0;
          Dwarf_Unsigned loc_count = 0;
          Dwarf_Unsigned i = 0;
          Dwarf_Unsigned meaninglesstotal = 0;

          res = dwarf_get_loclist_c(attr, &loclisthead, &loc_count, errp);
          if (res == DW_DLV_OK) {

            Dwarf_Addr localhighpc = 0;
            Dwarf_Half form = 0;
            enum Dwarf_Form_Class formclass = DW_FORM_CLASS_UNKNOWN;

            res = dwarf_highpc_b(die, &localhighpc, &form, &formclass, errp);

            if (form != DW_FORM_addr && !dwarf_addr_form_is_indexed(form)) {
              Dwarf_Addr low_pc = 0;
              res = dwarf_lowpc(die, &low_pc, errp);
              if (res != DW_DLV_OK) {
                dwarf_finish(dbg);
                close(fuzz_fd);
                unlink(filename);
                return res;
              } else {
                localhighpc += low_pc;
              }
            }
            for (i = 0; i < loc_count; ++i) {
              Dwarf_Small loclist_lkind = 0;
              Dwarf_Small lle_value = 0;
              Dwarf_Unsigned rawval1 = 0;
              Dwarf_Unsigned rawval2 = 0;
              Dwarf_Bool debug_addr_unavailable = 0;
              Dwarf_Addr lopc = 0;
              Dwarf_Addr hipc = 0;
              Dwarf_Unsigned loclist_expr_op_count = 0;
              Dwarf_Locdesc_c locdesc_entry = 0;
              Dwarf_Unsigned expression_offset = 0;
              Dwarf_Unsigned locdesc_offset = 0;

              res = dwarf_get_locdesc_entry_d(loclisthead, i, &lle_value, &rawval1, &rawval2, &debug_addr_unavailable, &lopc, &hipc, &loclist_expr_op_count, &locdesc_entry, &loclist_lkind, &expression_offset, &locdesc_offset, errp);
              if (res == DW_DLV_OK) {
                Dwarf_Unsigned j = 0;
                int opres = 0;
                Dwarf_Small op = 0;

                for (j = 0; j < loclist_expr_op_count; ++j) {
                  Dwarf_Unsigned opd1 = 0;
                  Dwarf_Unsigned opd2 = 0;
                  Dwarf_Unsigned opd3 = 0;
                  Dwarf_Unsigned offsetforbranch = 0;

                  opres = dwarf_get_location_op_value_c(locdesc_entry, j, &op, &opd1, &opd2, &opd3, &offsetforbranch, errp);
                }
              }
            }
            dwarf_dealloc_loc_head_c(loclisthead);
          }
        }
        dwarf_dealloc(dbg, cu_die, DW_DLA_DIE);
      }
    }
  }
  dwarf_finish(dbg);
  close(fuzz_fd);
  unlink(filename);
  return 0;
}
