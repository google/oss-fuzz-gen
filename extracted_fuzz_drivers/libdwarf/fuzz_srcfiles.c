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

#ifndef O_BINARY
#define O_BINARY 0
#endif

int examplee(Dwarf_Debug dbg, Dwarf_Die somedie, Dwarf_Error *error);
int exampled(Dwarf_Die somedie, Dwarf_Error *error);
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
        res = dwarf_siblingof_b(dbg, NULL, is_info, &cu_die, errp);
        if (res == DW_DLV_OK) {
          examplee(dbg, cu_die, errp);
          exampled(cu_die, errp);
        } else {
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

int examplee(Dwarf_Debug dbg, Dwarf_Die somedie, Dwarf_Error *error) {
  Dwarf_Signed count = 0;
  char **srcfiles = 0;
  Dwarf_Signed i = 0;
  int res = 0;

  res = dwarf_srcfiles(somedie, &srcfiles, &count, error);
  if (res != DW_DLV_OK) {
    return res;
  }
  for (i = 0; i < count; ++i) {
    dwarf_dealloc(dbg, srcfiles[i], DW_DLA_STRING);
  }
  dwarf_dealloc(dbg, srcfiles, DW_DLA_LIST);
  return DW_DLV_OK;
}

int exampled(Dwarf_Die somedie, Dwarf_Error *error) {
  Dwarf_Signed count = 0;
  Dwarf_Line_Context context = 0;
  Dwarf_Line *linebuf = 0;
  Dwarf_Signed i = 0;
  Dwarf_Line line;
  Dwarf_Small table_count = 0;
  Dwarf_Unsigned version = 0;
  int sres = 0;

  int lineheader_errcount = 0;
  dwarf_check_lineheader_b(somedie, &lineheader_errcount, error);
  dwarf_print_lines(somedie, error, &lineheader_errcount);

  sres = dwarf_srclines_b(somedie, &version, &table_count, &context, error);
  if (sres != DW_DLV_OK) {
    return sres;
  }
  sres = dwarf_srclines_from_linecontext(context, &linebuf, &count, error);
  if (sres != DW_DLV_OK) {
    dwarf_srclines_dealloc_b(context);
    return sres;
  }

  Dwarf_Line *dw_linebuf_actuals = 0;    /* init by davea*/
  Dwarf_Signed dw_linecount_actuals = 0; /* init by davea*/

  sres = dwarf_srclines_two_level_from_linecontext(context, &linebuf, &count, &dw_linebuf_actuals, &dw_linecount_actuals, error);
  if (sres != DW_DLV_OK) {
    dwarf_srclines_dealloc_b(context);
    return sres;
  }

  Dwarf_Unsigned dw_context_section_offset = 0; /* init by davea*/
  sres = dwarf_srclines_table_offset(context, &dw_context_section_offset, error);
  if (sres != DW_DLV_OK) {
    dwarf_srclines_dealloc_b(context);
    return sres;
  }

  const char *dw_compilation_directory = 0; /* init by davea*/
  sres = dwarf_srclines_comp_dir(context, &dw_compilation_directory, error);
  if (sres != DW_DLV_OK) {
    dwarf_srclines_dealloc_b(context);
    return sres;
  }

  Dwarf_Signed subprogram_count = 0; /* init by davea*/
  sres = dwarf_srclines_subprog_count(context, &subprogram_count, error);
  if (sres != DW_DLV_OK) {
    dwarf_srclines_dealloc_b(context);
    return sres;
  }

  Dwarf_Unsigned version_2 = 0;  /* init by davea*/
  Dwarf_Small table_count_2 = 0; /* init by davea*/
  dwarf_srclines_version(context, &version_2, &table_count_2, error);

  Dwarf_Signed dw_baseindex = 0; /* init by davea*/
  Dwarf_Signed dw_count = 0;     /* init by davea*/
  Dwarf_Signed dw_endindex = 0;  /* init by davea*/
  sres = dwarf_srclines_files_indexes(context, &dw_baseindex, &dw_count, &dw_endindex, error);
  if (sres != DW_DLV_OK) {
    dwarf_srclines_dealloc_b(context);
    return sres;
  }

  for (i = 0; i < subprogram_count; i++) {
    const char *dw_name = 0;         /* init by davea*/
    Dwarf_Unsigned dw_decl_file = 0; /* init by davea*/
    Dwarf_Unsigned dw_decl_line = 0; /* init by davea*/
    sres = dwarf_srclines_subprog_data(context, i + 1, &dw_name, &dw_decl_file, &dw_decl_line, error);
    if (sres != DW_DLV_OK) {
      continue;
    }
  }

  for (i = 0; i < count; ++i) {
    line = linebuf[i];

    Dwarf_Bool ans = 0;         /* init by davea */
    Dwarf_Unsigned linenum = 0; /* init by davea */
    dwarf_linebeginstatement(line, &ans, error);
    dwarf_lineendsequence(line, &ans, error);
    dwarf_line_is_addr_set(line, &ans, error);

    dwarf_lineno(line, &linenum, error);
    dwarf_line_srcfileno(line, &linenum, error);
    dwarf_lineoff_b(line, &linenum, error);

    char *linesrc = 0; /* INIT by davea */

    dwarf_linesrc(line, &linesrc, error);

    Dwarf_Bool prologue_end = 0;      /* init by davea*/
    Dwarf_Bool epilogue_begin = 0;    /* init by davea*/
    Dwarf_Unsigned isa = 0;           /* init by davea*/
    Dwarf_Unsigned discriminator = 0; /* init by davea*/
    dwarf_prologue_end_etc(line, &prologue_end, &epilogue_begin, &isa, &discriminator, error);

#if 1                             /* this is problematic and does not work */
    Dwarf_Unsigned l_logical = 0; /* init by davea*/
    dwarf_linelogical(line, &l_logical, error);

    Dwarf_Unsigned subprog_no = 0; /* init by davea*/
    dwarf_line_subprogno(line, &subprog_no, error);
#endif
  }
  dwarf_srclines_dealloc_b(context);
  return DW_DLV_OK;
}
