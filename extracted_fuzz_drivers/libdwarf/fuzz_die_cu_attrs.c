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
          Dwarf_Unsigned unsign = 0;
          res = dwarf_bytesize(cu_die, &unsign, errp);
          res = dwarf_bitsize(cu_die, &unsign, errp);
          res = dwarf_arrayorder(cu_die, &unsign, errp);

          Dwarf_Off section_offset = 0;
          Dwarf_Off local_offset = 0;
          res = dwarf_die_offsets(cu_die, &section_offset, &local_offset, errp);

          Dwarf_Off off = 0;
          res = dwarf_dietype_offset(die, &off, &is_info, &error);

          Dwarf_Off agoff = 0;
          Dwarf_Unsigned acount = 0;
          res = dwarf_die_abbrev_global_offset(cu_die, &agoff, &acount, errp);

          Dwarf_Bool someinfo = dwarf_get_die_infotypes_flag(cu_die);

          Dwarf_Off globaloff = 0;
          Dwarf_Unsigned length = 0;
          res = dwarf_die_CU_offset_range(cu_die, &globaloff, &length, errp);

          Dwarf_Half address_size = 0;
          res = dwarf_get_address_size(dbg, &address_size, errp);

          Dwarf_Unsigned offcnt = 0;
          Dwarf_Off *offbuf = 0;
          res = dwarf_offset_list(dbg, section_offset, is_info, &offbuf, &offcnt, errp);

          Dwarf_Off die_goff = 0;
          res = dwarf_dieoffset(cu_die, &die_goff, errp);

          int abbrev_code = dwarf_die_abbrev_code(cu_die);

          Dwarf_Bool has_attr = 0;
          res = dwarf_hasattr(cu_die, DW_AT_external, &has_attr, errp);

          Dwarf_Bool is_dwo = 0;
          Dwarf_Half offset_size = 0;
          Dwarf_Off offset_of_length = 0;
          Dwarf_Unsigned total_byte_length = 0;
          Dwarf_Sig8 *typesign = 0;

          res = dwarf_cu_header_basics(cu_die, &version_stamp, &is_info, &is_dwo, &offset_size, &address_size, &extension_size, &typesign, &offset_of_length, &total_byte_length, errp);

          Dwarf_Debug_Fission_Per_CU percu;
          memset(&percu, 0, sizeof(percu));
          res = dwarf_get_debugfission_for_die(cu_die, &percu, errp);
          char *name = 0;
          Dwarf_Half tag = 0;
          const char *tagname = 0;
          int res = 0;
          Dwarf_Attribute *atlist = 0;
          Dwarf_Signed atcount = 0;
          Dwarf_Attribute attr = 0;
          Dwarf_Half formnum = 0;
          const char *formname = "form-name-unavailable";

          if (res == DW_DLV_ERROR || res == DW_DLV_NO_ENTRY) {
            dwarf_dealloc(dbg, cu_die, DW_DLA_DIE);
            dwarf_finish(dbg);
            close(fuzz_fd);
            return 0;
          }

          res = dwarf_diename(cu_die, &name, errp);

          res = dwarf_get_TAG_name(tag, &tagname);

          res = dwarf_attr(cu_die, DW_AT_name, &attr, errp);
          res = dwarf_attrlist(cu_die, &atlist, &atcount, errp);
          for (i = 0; i < atcount; ++i) {
            Dwarf_Half attrnum = 0;
            const char *attrname = 0;
            res = dwarf_whatform(attr, &formnum, errp);
            Dwarf_Bool *dw_returned_bool = 0;
            /*  This next call is incorrect! libdwarf now returns
                DW_DLV_ERROR  */
            res = dwarf_hasform(attr, formnum, dw_returned_bool, errp);
            res = dwarf_get_FORM_name(formnum, &formname);
            Dwarf_Block *tempb = 0;
            res = dwarf_formblock(attr, &tempb, errp);
            if (res == DW_DLV_OK) {
              Dwarf_Dsc_Head h = 0;
              /* Dwarf_Unsigned u = 0; unused */
              Dwarf_Unsigned arraycount = 0;
              int sres = 0;

              sres = dwarf_discr_list(dbg, (Dwarf_Small *)tempb->bl_data, tempb->bl_len, &h, &arraycount, errp);
            }
            res = dwarf_whatattr(atlist[i], &attrnum, errp);
            dwarf_get_AT_name(attrnum, &attrname);
            dwarf_dealloc_attribute(atlist[i]);
            atlist[i] = 0;
            char *stringval = 0;
            res = dwarf_bitoffset(cu_die, &attrnum, &unsign, errp);
            res = dwarf_die_text(cu_die, attrnum, &stringval, errp);
            res = dwarf_get_form_class(version_stamp, attrnum, next_cu_header_offset, formnum);
          }
          res = dwarf_set_tied_dbg(dbg, NULL, errp);
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
