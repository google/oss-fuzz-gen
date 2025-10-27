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
// #include <config.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

/*
 * Libdwarf library callers can only use these headers.
 */
#include "dwarf.h"
#include "libdwarf.h"

#define DW_PR_DUx "llx"
#define DW_PR_DSx "llx"
#define DW_PR_DUu "llu"
#define DW_PR_DSd "lld"

#define TRUE 1
#define FALSE 0
static int unittype = DW_UT_compile;
static Dwarf_Bool g_is_info = FALSE;

int cu_version_stamp = 0;
int cu_offset_size = 0;

struct srcfilesdata {
  char **srcfiles;
  Dwarf_Signed srcfilescount;
  int srcfilesres;
};
struct target_data_s {
  Dwarf_Debug td_dbg;
  Dwarf_Unsigned td_target_pc; /* from argv */
  int td_print_details;        /* from argv */
  int td_reportallfound;       /* from argv */

  /*  cu die data. */
  Dwarf_Unsigned td_cu_lowpc;
  Dwarf_Unsigned td_cu_highpc;
  int td_cu_haslowhighpc;
  Dwarf_Die td_cu_die;
  char *td_cu_name;
  char *td_cu_comp_dir;
  Dwarf_Unsigned td_cu_number;
  struct srcfilesdata td_cu_srcfiles;
  Dwarf_Unsigned td_cu_ranges_base;

  Dwarf_Off td_ranges_offset;
  char *td_subprog_name;
  Dwarf_Unsigned td_subprog_fileindex;
  Dwarf_Die td_subprog_die;
  Dwarf_Unsigned td_subprog_lowpc;
  Dwarf_Unsigned td_subprog_highpc;
  int td_subprog_haslowhighpc;
  Dwarf_Unsigned td_subprog_lineaddr;
  Dwarf_Unsigned td_subprog_lineno;
  char *td_subprog_srcfile; /* dealloc */
};
#define NOT_THIS_CU 10
#define IN_THIS_CU 11
#define FOUND_SUBPROG 12

static int look_for_our_target(Dwarf_Debug dbg, struct target_data_s *target_data, Dwarf_Error *errp);
static int examine_die_data(Dwarf_Debug dbg, int is_info, Dwarf_Die die, int level, struct target_data_s *td, Dwarf_Error *errp);
static int check_comp_dir(Dwarf_Debug dbg, Dwarf_Die die, struct target_data_s *td, Dwarf_Error *errp);
static int get_die_and_siblings(Dwarf_Debug dbg, Dwarf_Die in_die, int is_info, int in_level, int cu_number, struct target_data_s *td, Dwarf_Error *errp);

#if 0
DW_UT_compile                   0x01  /* DWARF5 */
DW_UT_type                      0x02  /* DWARF5 */
DW_UT_partial                   0x03  /* DWARF5 */
#endif

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  char filepath[256];
  sprintf(filepath, "/tmp/libfuzzer.%d", getpid());

  FILE *fp = fopen(filepath, "wb");
  if (!fp) {
    return 0;
  }
  fwrite(data, size, 1, fp);
  fclose(fp);

  Dwarf_Debug dbg = 0;
  Dwarf_Error error = 0;
  Dwarf_Handler errhand = 0;
  Dwarf_Ptr errarg = 0;
  int i = 0;
  Dwarf_Unsigned target_pc = 0x1000;
#define PATH_LEN 2000
  char real_path[PATH_LEN];
  struct target_data_s target_data;

  /*  Added 19 May 2023 so valgrind will not complain
      about testing uninitialized values in
      check_coup_dir (for example). */
  memset(&target_data, 0, sizeof(target_data));
  int res = dwarf_init_path(filepath, 0, 0, DW_GROUPNUMBER_ANY, 0, 0, &dbg, &error);
  if (res == DW_DLV_ERROR) {
    dwarf_dealloc_error(dbg, error);
    dwarf_finish(dbg);
  } else {
    res = look_for_our_target(dbg, &target_data, &error);
    res = dwarf_finish(dbg);
  }

  unlink(filepath);
  return 0;
}

static int read_line_data(Dwarf_Debug dbg, struct target_data_s *td, Dwarf_Error *errp) {
  int res = 0;
  Dwarf_Unsigned line_version = 0;
  Dwarf_Small table_type = 0;
  Dwarf_Line_Context line_context = 0;
  Dwarf_Signed i = 0;
  Dwarf_Signed baseindex = 0;
  Dwarf_Signed endindex = 0;
  Dwarf_Signed file_count = 0;
  Dwarf_Unsigned dirindex = 0;

  (void)dbg;
  res = dwarf_srclines_b(td->td_cu_die, &line_version, &table_type, &line_context, errp);
  if (res != DW_DLV_OK) {
    return res;
  }
  if (table_type == 0) {
    int sres = 0;

    sres = dwarf_srclines_files_indexes(line_context, &baseindex, &file_count, &endindex, errp);
    if (sres != DW_DLV_OK) {
      dwarf_srclines_dealloc_b(line_context);
      line_context = 0;
      return sres;
    }
    for (i = baseindex; i < endindex; i++) {
      Dwarf_Unsigned modtime = 0;
      Dwarf_Unsigned flength = 0;
      Dwarf_Form_Data16 *md5data = 0;
      int vres = 0;
      const char *name = 0;

      vres = dwarf_srclines_files_data_b(line_context, i, &name, &dirindex, &modtime, &flength, &md5data, errp);
      if (vres != DW_DLV_OK) {
        dwarf_srclines_dealloc_b(line_context);
        line_context = 0;
        return vres;
      }
    }
    dwarf_srclines_dealloc_b(line_context);
    return DW_DLV_OK;
  } else if (table_type == 1) {
    const char *dir_name = 0;
    int sres = 0;
    Dwarf_Line *linebuf = 0;
    Dwarf_Signed linecount = 0;
    Dwarf_Signed dir_count = 0;
    Dwarf_Addr prev_lineaddr = 0;
    Dwarf_Unsigned prev_lineno = 0;
    char *prev_linesrcfile = 0;

    sres = dwarf_srclines_files_indexes(line_context, &baseindex, &file_count, &endindex, errp);
    if (sres != DW_DLV_OK) {
      dwarf_srclines_dealloc_b(line_context);
      line_context = 0;
      return sres;
    }
    for (i = baseindex; i < endindex; i++) {
      Dwarf_Unsigned dirindexb = 0;
      Dwarf_Unsigned modtime = 0;
      Dwarf_Unsigned flength = 0;
      Dwarf_Form_Data16 *md5data = 0;
      int vres = 0;
      const char *name = 0;

      vres = dwarf_srclines_files_data_b(line_context, i, &name, &dirindexb, &modtime, &flength, &md5data, errp);
      if (vres != DW_DLV_OK) {
        dwarf_srclines_dealloc_b(line_context);
        line_context = 0;
        return vres;
      }
    }
    sres = dwarf_srclines_include_dir_count(line_context, &dir_count, errp);
    if (sres != DW_DLV_OK) {
      dwarf_srclines_dealloc_b(line_context);
      line_context = 0;
      return sres;
    }

    for (i = 1; i <= dir_count; ++i) {
      dir_name = 0;
      sres = dwarf_srclines_include_dir_data(line_context, i, &dir_name, errp);
      if (sres == DW_DLV_ERROR) {
        dwarf_srclines_dealloc_b(line_context);
        line_context = 0;
        return sres;
      }
    }

    sres = dwarf_srclines_from_linecontext(line_context, &linebuf, &linecount, errp);
    if (sres != DW_DLV_OK) {
      dwarf_srclines_dealloc_b(line_context);
      line_context = 0;
      return sres;
    }
    for (i = 0; i < linecount; ++i) {
      Dwarf_Addr lineaddr = 0;
      Dwarf_Unsigned filenum = 0;
      Dwarf_Unsigned lineno = 0;
      char *linesrcfile = 0;

      sres = dwarf_lineno(linebuf[i], &lineno, errp);
      if (sres == DW_DLV_ERROR) {
        if (prev_linesrcfile) {
          dwarf_dealloc(dbg, prev_linesrcfile, DW_DLA_STRING);
        }
        return sres;
      }
      sres = dwarf_line_srcfileno(linebuf[i], &filenum, errp);
      if (sres == DW_DLV_ERROR) {
        if (prev_linesrcfile) {
          dwarf_dealloc(dbg, prev_linesrcfile, DW_DLA_STRING);
        }
        return sres;
      }
      if (filenum) {
        filenum -= 1;
      }
      sres = dwarf_lineaddr(linebuf[i], &lineaddr, errp);
      if (sres == DW_DLV_ERROR) {
        if (prev_linesrcfile) {
          dwarf_dealloc(dbg, prev_linesrcfile, DW_DLA_STRING);
        }
        return sres;
      }
      sres = dwarf_linesrc(linebuf[i], &linesrcfile, errp);
      if (sres == DW_DLV_ERROR) {
        if (prev_linesrcfile) {
          dwarf_dealloc(dbg, prev_linesrcfile, DW_DLA_STRING);
        }
        return sres;
      }
      if (lineaddr > td->td_target_pc) {
        td->td_subprog_lineaddr = prev_lineaddr;
        td->td_subprog_lineno = prev_lineno;
        td->td_subprog_srcfile = prev_linesrcfile;
        dwarf_dealloc(dbg, linesrcfile, DW_DLA_STRING);
        return DW_DLV_OK;
      }
      prev_lineaddr = lineaddr;
      prev_lineno = lineno;
      if (prev_linesrcfile) {
        dwarf_dealloc(dbg, prev_linesrcfile, DW_DLA_STRING);
      }
      prev_linesrcfile = linesrcfile;
    }
    td->td_subprog_lineaddr = prev_lineaddr;
    td->td_subprog_lineno = prev_lineno;
    td->td_subprog_srcfile = prev_linesrcfile;
    dwarf_srclines_dealloc_b(line_context);
    return DW_DLV_OK;
  }
  return DW_DLV_ERROR;
}

static int look_for_our_target(Dwarf_Debug dbg, struct target_data_s *td, Dwarf_Error *errp) {
  Dwarf_Unsigned cu_header_length = 0;
  Dwarf_Unsigned abbrev_offset = 0;
  Dwarf_Half address_size = 0;
  Dwarf_Half version_stamp = 0;
  Dwarf_Half offset_size = 0;
  Dwarf_Half extension_size = 0;
  Dwarf_Unsigned typeoffset = 0;
  Dwarf_Half header_cu_type = unittype;
  Dwarf_Bool is_info = g_is_info;
  int cu_number = 0;

  for (;; ++cu_number) {
    Dwarf_Die no_die = 0;
    Dwarf_Die cu_die = 0;
    int res = DW_DLV_ERROR;
    Dwarf_Sig8 signature;

    memset(&signature, 0, sizeof(signature));
    res = dwarf_next_cu_header_d(dbg, is_info, &cu_header_length, &version_stamp, &abbrev_offset, &address_size, &offset_size, &extension_size, &signature, &typeoffset, 0, &header_cu_type, errp);
    if (res == DW_DLV_ERROR) {
      if (errp) {
        char *em = dwarf_errmsg(*errp);
      }
      return DW_DLV_NO_ENTRY;
    }
    if (res == DW_DLV_NO_ENTRY) {
      return DW_DLV_NO_ENTRY;
    }
    cu_version_stamp = version_stamp;
    cu_offset_size = offset_size;
    res = dwarf_siblingof_b(dbg, no_die, is_info, &cu_die, errp);
    if (res == DW_DLV_ERROR) {
      if (errp) {
        char *em = dwarf_errmsg(*errp);
      }
      return res;
    }
    if (res == DW_DLV_NO_ENTRY) {
      return res;
    }

    td->td_cu_die = cu_die;
    res = get_die_and_siblings(dbg, cu_die, is_info, 0, cu_number, td, errp);
    if (res == FOUND_SUBPROG) {
      read_line_data(dbg, td, errp);
      if (td->td_reportallfound) {
        return res;
      }
      return res;
    } else if (res == IN_THIS_CU) {
      if (errp) {
        char *em = dwarf_errmsg(*errp);
      }
      return res;
    } else if (res == DW_DLV_ERROR) {
      if (errp) {
        char *em = dwarf_errmsg(*errp);
      }
      return DW_DLV_ERROR;
    }
    return DW_DLV_NO_ENTRY;
  }
}

static int get_die_and_siblings(Dwarf_Debug dbg, Dwarf_Die in_die, int is_info, int in_level, int cu_number, struct target_data_s *td, Dwarf_Error *errp) {
  int res = DW_DLV_ERROR;
  Dwarf_Die cur_die = in_die;
  Dwarf_Die child = 0;

  td->td_cu_number = cu_number;
  res = examine_die_data(dbg, is_info, in_die, in_level, td, errp);
  if (res == DW_DLV_ERROR) {
    return res;
  }
  if (res == DW_DLV_NO_ENTRY) {
    return res;
  }
  if (res == NOT_THIS_CU) {
    return res;
  } else if (res == FOUND_SUBPROG) {
    return res;
  } else {
  }

  for (;;) {
    Dwarf_Die sib_die = 0;
    res = dwarf_child(cur_die, &child, errp);
    if (res == DW_DLV_ERROR) {
      return res;
    }
    if (res == DW_DLV_OK) {
      int res2 = 0;

      res2 = get_die_and_siblings(dbg, child, is_info, in_level + 1, cu_number, td, errp);
      if (child != td->td_cu_die && child != td->td_subprog_die) {
        dwarf_dealloc(dbg, child, DW_DLA_DIE);
      }
      if (res2 == FOUND_SUBPROG) {
        return res2;
      } else if (res2 == IN_THIS_CU) {
      } else if (res2 == NOT_THIS_CU) {
        return res2;
      } else if (res2 == DW_DLV_ERROR) {
        return res2;
      } else if (res2 == DW_DLV_NO_ENTRY) {
      } else { /* DW_DLV_OK */
      }
      child = 0;
    }
    res = dwarf_siblingof_b(dbg, cur_die, is_info, &sib_die, errp);
    if (res == DW_DLV_ERROR) {
      if (errp) {
        char *em = dwarf_errmsg(*errp);
      }
      return res;
    }
    if (res == DW_DLV_NO_ENTRY) {
      break;
    }
    if (cur_die != in_die) {
      if (child != td->td_cu_die && child != td->td_subprog_die) {
        dwarf_dealloc(dbg, cur_die, DW_DLA_DIE);
      }
      cur_die = 0;
    }
    cur_die = sib_die;
    res = examine_die_data(dbg, is_info, cur_die, in_level, td, errp);
    if (res == DW_DLV_ERROR) {
      return res;
    } else if (res == DW_DLV_OK) {
    } else if (res == FOUND_SUBPROG) {
      return res;
    } else if (res == NOT_THIS_CU) {
    } else if (res == IN_THIS_CU) {
    } else {
    }
  }
  return DW_DLV_OK;
}

static void dealloc_rest_of_list(Dwarf_Debug dbg, Dwarf_Attribute *attrbuf, Dwarf_Signed attrcount, Dwarf_Signed i) {
  for (; i < attrcount; ++i) {
    dwarf_dealloc_attribute(attrbuf[i]);
  }
  dwarf_dealloc(dbg, attrbuf, DW_DLA_LIST);
}

static int getlowhighpc(Dwarf_Die die, int *have_pc_range, Dwarf_Addr *lowpc_out, Dwarf_Addr *highpc_out, Dwarf_Error *error) {
  Dwarf_Addr hipc = 0;
  int res = 0;
  Dwarf_Half form = 0;
  enum Dwarf_Form_Class formclass = 0;

  *have_pc_range = FALSE;
  res = dwarf_lowpc(die, lowpc_out, error);
  if (res == DW_DLV_OK) {
    res = dwarf_highpc_b(die, &hipc, &form, &formclass, error);
    if (res == DW_DLV_OK) {
      if (formclass == DW_FORM_CLASS_CONSTANT) {
        hipc += *lowpc_out;
      }
      *highpc_out = hipc;
      *have_pc_range = TRUE;
      return DW_DLV_OK;
    }
  }
  return DW_DLV_NO_ENTRY;
}

static int check_subprog_ranges_for_match(Dwarf_Debug dbg, Dwarf_Die die, struct target_data_s *td, int *have_pc_range, Dwarf_Addr *lowpc_out, Dwarf_Addr *highpc_out, Dwarf_Error *errp) {
  int res = 0;
  Dwarf_Ranges *ranges;
  Dwarf_Signed ranges_count;
  Dwarf_Unsigned byte_count;
  Dwarf_Signed i = 0;
  Dwarf_Addr baseaddr = 0;
  Dwarf_Off actualoffset = 0;
  int done = FALSE;

  res = dwarf_get_ranges_b(dbg, td->td_ranges_offset, die, &actualoffset, &ranges, &ranges_count, &byte_count, errp);
  if (res != DW_DLV_OK) {
    return res;
  }
  for (i = 0; i < ranges_count && !done; ++i) {
    Dwarf_Ranges *cur = ranges + i;
    Dwarf_Addr lowpc = 0;
    Dwarf_Addr highpc = 0;
    switch (cur->dwr_type) {
    case DW_RANGES_ENTRY:
      lowpc = cur->dwr_addr1 + baseaddr;
      highpc = cur->dwr_addr2 + baseaddr;
      if (td->td_target_pc < lowpc || td->td_target_pc >= highpc) {
        break;
      }
      *lowpc_out = lowpc;
      *highpc_out = highpc;
      *have_pc_range = TRUE;
      done = TRUE;
      res = FOUND_SUBPROG;
      break;
    case DW_RANGES_ADDRESS_SELECTION:
      baseaddr = cur->dwr_addr2;
      break;
    case DW_RANGES_END:
      break;
    default:
      return DW_DLV_ERROR;
    }
  }
  dwarf_dealloc_ranges(dbg, ranges, ranges_count);
  return res;
}

static int get_name_from_abstract_origin(Dwarf_Debug dbg, int is_info, Dwarf_Die die, char **name, Dwarf_Error *errp) {
  int res = 0;
  Dwarf_Die abrootdie = 0;
  Dwarf_Attribute ab_attr = 0;
  Dwarf_Off ab_offset = 0;

  res = dwarf_attr(die, DW_AT_abstract_origin, &ab_attr, errp);
  if (res != DW_DLV_OK) {
    return res;
  }

  res = dwarf_global_formref(ab_attr, &ab_offset, errp);
  if (res != DW_DLV_OK) {
    dwarf_dealloc(dbg, ab_attr, DW_DLA_ATTR);
    return res;
  }

  dwarf_dealloc(dbg, ab_attr, DW_DLA_ATTR);
  res = dwarf_offdie_b(dbg, ab_offset, is_info, &abrootdie, errp);
  if (res != DW_DLV_OK) {
    return res;
  }
  res = dwarf_diename(abrootdie, name, errp);
  dwarf_dealloc_die(abrootdie);
  return res;
}

static int check_subprog_details(Dwarf_Debug dbg, int is_info, Dwarf_Die die, struct target_data_s *td, int *have_pc_range_out, Dwarf_Addr *lowpc_out, Dwarf_Addr *highpc_out, Dwarf_Error *errp) {
  int res = 0;
  Dwarf_Addr lowpc = 0;
  Dwarf_Addr highpc = 0;
  int finalres = 0;
  int have_pc_range = FALSE;

  res = getlowhighpc(die, &have_pc_range, &lowpc, &highpc, errp);
  if (res == DW_DLV_OK) {
    if (have_pc_range) {
      int res2 = DW_DLV_OK;
      char *name = 0;

      if (td->td_target_pc < lowpc || td->td_target_pc >= highpc) {
        finalres = DW_DLV_OK;
      } else {
        td->td_subprog_die = die;
        td->td_subprog_lowpc = lowpc;
        *lowpc_out = lowpc;
        *highpc_out = highpc;
        *have_pc_range_out = have_pc_range;
        td->td_subprog_highpc = highpc;
        td->td_subprog_haslowhighpc = have_pc_range;
        res2 = dwarf_diename(die, &name, errp);
        if (res2 == DW_DLV_OK) {
          td->td_subprog_name = name;
        } else {
          get_name_from_abstract_origin(dbg, is_info, die, &name, errp);
        }
        td->td_subprog_name = name;
        name = 0;
        finalres = FOUND_SUBPROG;
      }
    }
  }
  {
    Dwarf_Signed i = 0;
    Dwarf_Signed atcount = 0;
    Dwarf_Attribute *atlist = 0;

    res = dwarf_attrlist(die, &atlist, &atcount, errp);
    if (res != DW_DLV_OK) {
      return res;
    }
    for (i = 0; i < atcount; ++i) {
      Dwarf_Half atr = 0;
      Dwarf_Attribute attrib = atlist[i];

      res = dwarf_whatattr(attrib, &atr, errp);
      if (res != DW_DLV_OK) {
        dealloc_rest_of_list(dbg, atlist, atcount, i);
        return res;
      }
      if (atr == DW_AT_ranges) {
        int res2 = 0;
        int res4 = 0;
        Dwarf_Off ret_offset = 0;
        int has_low_hi = FALSE;
        Dwarf_Addr low = 0;
        Dwarf_Addr high = 0;

        res2 = dwarf_global_formref(attrib, &ret_offset, errp);
        if (res2 != DW_DLV_OK) {
          dealloc_rest_of_list(dbg, atlist, atcount, i);
          return res2;
        }
        td->td_ranges_offset = ret_offset + td->td_cu_ranges_base;
        res4 = check_subprog_ranges_for_match(dbg, die, td, &has_low_hi, &low, &high, errp);
        if (res4 == DW_DLV_OK) {
          continue;
        }
        if (res4 == DW_DLV_NO_ENTRY) {
          continue;
        }
        if (res4 == FOUND_SUBPROG) {
          td->td_subprog_lowpc = lowpc;
          td->td_subprog_highpc = highpc;
          td->td_subprog_haslowhighpc = has_low_hi;
          finalres = FOUND_SUBPROG;
          continue;
        }
        dealloc_rest_of_list(dbg, atlist, atcount, i);
        return res4;
      } else if (atr == DW_AT_decl_file) {
        int res5 = 0;
        Dwarf_Unsigned file_index = 0;

        res5 = dwarf_formudata(attrib, &file_index, errp);
        if (res5 != DW_DLV_OK) {
          dealloc_rest_of_list(dbg, atlist, atcount, i);
          return res5;
        }
        td->td_subprog_fileindex = file_index;
      }
      dwarf_dealloc(dbg, attrib, DW_DLA_ATTR);
    }
    dwarf_dealloc(dbg, atlist, DW_DLA_LIST);
  }
  return finalres;
}

static int check_comp_dir(Dwarf_Debug dbg, Dwarf_Die die, struct target_data_s *td, Dwarf_Error *errp) {
  int res = 0;
  int finalres = DW_DLV_NO_ENTRY;
  int have_pc_range = FALSE;
  Dwarf_Addr lowpc = 0;
  Dwarf_Addr highpc = 0;
  Dwarf_Off real_ranges_offset = 0;
  int rdone = FALSE;

  res = getlowhighpc(die, &have_pc_range, &lowpc, &highpc, errp);
  if (res == DW_DLV_OK) {
    if (have_pc_range) {
      if (td->td_target_pc < lowpc || td->td_target_pc >= highpc) {
        res = NOT_THIS_CU;
      } else {
        td->td_cu_lowpc = lowpc;
        td->td_cu_highpc = highpc;
        res = IN_THIS_CU;
      }
    }
  }
  finalres = res;
  {
    Dwarf_Signed atcount = 0;
    Dwarf_Attribute *atlist = 0;
    Dwarf_Signed j = 0;
    int alres = 0;

    alres = dwarf_attrlist(die, &atlist, &atcount, errp);
    if (alres != DW_DLV_OK) {
      return alres;
    }
    for (j = 0; j < atcount; ++j) {
      Dwarf_Half atr = 0;
      Dwarf_Attribute attrib = atlist[j];
      int resb = 0;

      resb = dwarf_whatattr(attrib, &atr, errp);
      if (resb != DW_DLV_OK) {
        dwarf_dealloc(dbg, atlist, DW_DLA_LIST);
        return resb;
      }
      if (atr == DW_AT_name) {
        char *name = 0;
        resb = dwarf_formstring(attrib, &name, errp);
        if (resb == DW_DLV_OK) {
          td->td_cu_name = name;
        }
      } else if (atr == DW_AT_comp_dir) {
        char *name = 0;
        resb = dwarf_formstring(attrib, &name, errp);
        if (resb == DW_DLV_OK) {
          td->td_cu_comp_dir = name;
        }
      } else if (atr == DW_AT_rnglists_base || atr == DW_AT_GNU_ranges_base) {
        Dwarf_Off rbase = 0;

        resb = dwarf_global_formref(attrib, &rbase, errp);
        if (resb != DW_DLV_OK) {
          dwarf_dealloc(dbg, atlist, DW_DLA_LIST);
          return resb;
        }
        td->td_cu_ranges_base = rbase;
      } else if (atr == DW_AT_ranges) {
        /* we have actual ranges. */
        Dwarf_Off rbase = 0;

        resb = dwarf_global_formref(attrib, &rbase, errp);
        if (resb != DW_DLV_OK) {
          dwarf_dealloc(dbg, atlist, DW_DLA_LIST);
          return resb;
        }
        real_ranges_offset = rbase;
        rdone = TRUE;
      }
      dwarf_dealloc(dbg, attrib, DW_DLA_ATTR);
    }
    dwarf_dealloc(dbg, atlist, DW_DLA_LIST);
  }
  if (rdone) {
    int resr = 0;
    Dwarf_Ranges *ranges = 0;
    Dwarf_Signed ranges_count = 0;
    Dwarf_Unsigned byte_count = 0;
    Dwarf_Off actualoffset = 0;
    Dwarf_Signed k = 0;
    int done = FALSE;

    resr = dwarf_get_ranges_b(dbg, real_ranges_offset, die, &actualoffset, &ranges, &ranges_count, &byte_count, errp);
    if (resr != DW_DLV_OK) {
      return res;
    }
    for (k = 0; k < ranges_count && !done; ++k) {
      Dwarf_Ranges *cur = ranges + k;
      Dwarf_Addr lowpcr = 0;
      Dwarf_Addr highpcr = 0;
      Dwarf_Addr baseaddr = td->td_cu_ranges_base;

      switch (cur->dwr_type) {
      case DW_RANGES_ENTRY:
        lowpc = cur->dwr_addr1 + baseaddr;
        highpc = cur->dwr_addr2 + baseaddr;
        if (td->td_target_pc < lowpc || td->td_target_pc >= highpc) {
          break;
        }
        td->td_cu_lowpc = lowpcr;
        td->td_cu_highpc = highpcr;
        td->td_cu_haslowhighpc = TRUE;
        done = TRUE;
        finalres = IN_THIS_CU;
        break;
      case DW_RANGES_ADDRESS_SELECTION:
        baseaddr = cur->dwr_addr2;
        break;
      case DW_RANGES_END:
        break;
      default:
        return DW_DLV_ERROR;
      }
    }
    dwarf_dealloc_ranges(dbg, ranges, ranges_count);
  }
  return finalres;
}

static int examine_die_data(Dwarf_Debug dbg, int is_info, Dwarf_Die die, int level, struct target_data_s *td, Dwarf_Error *errp) {
  Dwarf_Half tag = 0;
  int res = 0;

  res = dwarf_tag(die, &tag, errp);
  if (res != DW_DLV_OK) {
    return res;
  }
  if (tag == DW_TAG_subprogram || tag == DW_TAG_inlined_subroutine) {
    int have_pc_range = 0;
    Dwarf_Addr lowpc = 0;
    Dwarf_Addr highpc = 0;

    res = check_subprog_details(dbg, is_info, die, td, &have_pc_range, &lowpc, &highpc, errp);
    if (res == FOUND_SUBPROG) {
      td->td_subprog_die = die;
      return res;
    } else if (res == DW_DLV_ERROR) {
      return res;
    } else if (res == DW_DLV_NO_ENTRY) {
      /* impossible? */
      return res;
    } else if (res == NOT_THIS_CU) {
      /* impossible */
      return res;
    } else if (res == IN_THIS_CU) {
      /* impossible */
      return res;
    } else {
      /* DW_DLV_OK */
    }
    return DW_DLV_OK;
  } else if (tag == DW_TAG_compile_unit || tag == DW_TAG_partial_unit || tag == DW_TAG_type_unit) {

    if (level) {
      return NOT_THIS_CU;
    }
    res = check_comp_dir(dbg, die, td, errp);
    return res;
  }
  return DW_DLV_OK;
}
