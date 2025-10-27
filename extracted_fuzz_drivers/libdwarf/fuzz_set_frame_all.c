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
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#ifndef O_BINARY
#define O_BINARY 0 /* So it does nothing in Linux/Unix */
#endif
#define DW_PR_DUx "llx"
#define DW_PR_DSx "llx"
#define DW_PR_DUu "llu"
#define DW_PR_DSd "lld"

static void read_frame_data(Dwarf_Debug dbg, const char *sec);
static void print_fde_instrs(Dwarf_Debug dbg, Dwarf_Fde fde, Dwarf_Error *error);
static void print_regtable(Dwarf_Regtable3 *tab3);
static void print_cie_instrs(Dwarf_Cie cie, Dwarf_Error *error);
static void print_fde_selected_regs(Dwarf_Fde fde);
static void print_reg(int r);
static void dump_block(char *prefix, Dwarf_Small *data, Dwarf_Unsigned len);

#define UNDEF_VAL 2000
#define SAME_VAL 2001
#define CFA_VAL 2002
#define INITIAL_VAL UNDEF_VAL

/*  Because this code does exit() without
    calling dwarf_finish() in case of certain
    errors in corrupted objects, executing the program is
    guaranteed to leak memory when that class
    of errors is found in the object file being read.

    David Anderson

    As of 30 May 2023 all the exit() calls (other
    than the open() call) are changed to
    return; instead so we do not leak memory.
    In addition the tab3.rt3_rules the code mallocs
    here is always freed here now. */

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
    printf("Unable to open %s, giving up.\n", filename);
    exit(EXIT_FAILURE);
  }

  res = dwarf_init_b(fd, DW_GROUPNUMBER_ANY, errhand, errarg, &dbg, &error);

  if (res != DW_DLV_OK) {
    printf("Giving up, dwarf_init failed, "
           "cannot do DWARF processing\n");
    if (res == DW_DLV_ERROR) {
      printf("Error code %s\n", dwarf_errmsg(error));
    }
    dwarf_dealloc_error(dbg, error);
  } else {
    Dwarf_Half frame_values[] = {SHRT_MIN, SHRT_MAX, 0};
    for (int i = 0; i < 3; i++) {
      dwarf_set_frame_undefined_value(dbg, frame_values[i]);
      read_frame_data(dbg, ".debug_frame");
      read_frame_data(dbg, ".eh_frame");
    }
    for (int i = 0; i < 3; i++) {
      dwarf_set_frame_rule_initial_value(dbg, frame_values[i]);
      read_frame_data(dbg, ".debug_frame");
      read_frame_data(dbg, ".eh_frame");
    }
    for (int i = 0; i < 3; i++) {
      dwarf_set_frame_same_value(dbg, frame_values[i]);
      read_frame_data(dbg, ".debug_frame");
      read_frame_data(dbg, ".eh_frame");
    }
    for (int i = 0; i < 3; i++) {
      dwarf_set_frame_cfa_value(dbg, frame_values[i]);
      read_frame_data(dbg, ".debug_frame");
      read_frame_data(dbg, ".eh_frame");
    }
    for (int i = 0; i < 3; i++) {
      dwarf_set_frame_rule_table_size(dbg, frame_values[i]);
      read_frame_data(dbg, ".debug_frame");
      read_frame_data(dbg, ".eh_frame");
    }
  }

  res = dwarf_finish(dbg);
  close(fd);
  unlink(filename);
  return 0;
}

static void dump_block(char *prefix, Dwarf_Small *data, Dwarf_Unsigned len) {
  Dwarf_Small *end_data = data + len;
  Dwarf_Small *cur = data;
  int i = 0;

  printf("%s", prefix);
  for (; cur < end_data; ++cur, ++i) {
    if (i > 0 && i % 4 == 0)
      printf(" ");
    printf("%02x", 0xff & *cur);
  }
}

static void read_frame_data(Dwarf_Debug dbg, const char *sect) {
  Dwarf_Error error;
  Dwarf_Signed cie_element_count = 0;
  Dwarf_Signed fde_element_count = 0;
  Dwarf_Cie *cie_data = 0;
  Dwarf_Fde *fde_data = 0;
  int res = DW_DLV_ERROR;
  Dwarf_Signed fdenum = 0;

  printf(" Print %s\n", sect);
  if (!strcmp(sect, ".eh_frame")) {
    res = dwarf_get_fde_list_eh(dbg, &cie_data, &cie_element_count, &fde_data, &fde_element_count, &error);
  } else {
    res = dwarf_get_fde_list(dbg, &cie_data, &cie_element_count, &fde_data, &fde_element_count, &error);
  }
  if (res == DW_DLV_NO_ENTRY) {
    printf("No %s data present\n", sect);
    return;
  }
  if (res == DW_DLV_ERROR) {
    printf("Error reading frame data \n");
    return;
  }
  printf("%" DW_PR_DSd " cies present. "
         "%" DW_PR_DSd " fdes present. \n",
         cie_element_count, fde_element_count);
  for (fdenum = 0; fdenum < fde_element_count; ++fdenum) {
    Dwarf_Cie cie = 0;

    Dwarf_Fde fde;
    dwarf_get_fde_n(fde_data, fdenum, &fde, &error);

    res = dwarf_get_cie_of_fde(fde, &cie, &error);
    if (res != DW_DLV_OK) {
      printf("Error accessing cie of fdenum %" DW_PR_DSd " to get its cie\n", fdenum);
      return;
    }
    printf("Print cie of fde %" DW_PR_DSd "\n", fdenum);
    print_cie_instrs(cie, &error);
    printf("Print fde %" DW_PR_DSd "\n", fdenum);
    print_fde_selected_regs(fde_data[fdenum]);
    print_fde_instrs(dbg, fde_data[fdenum], &error);

    Dwarf_Signed dw_offset_into_exception_tables;
    Dwarf_Signed dw_idx;

    dwarf_get_fde_exception_info(fde_data[fdenum], &dw_offset_into_exception_tables, &error);
    dwarf_get_cie_index(cie, &dw_idx, &error);

    Dwarf_Small *dw_augdata;
    Dwarf_Unsigned dw_augdata_len;
    dwarf_get_cie_augmentation_data(cie, &dw_augdata, &dw_augdata_len, &error);

    Dwarf_Small *fde_augdata;
    Dwarf_Unsigned fde_augdata_len;
    dwarf_get_fde_augmentation_data(fde, &fde_augdata, &fde_augdata_len, &error);

    Dwarf_Off dw_fde_off;
    Dwarf_Off dw_cie_off;

    dwarf_fde_section_offset(dbg, fde, &dw_fde_off, &dw_cie_off, &error);
    dwarf_cie_section_offset(dbg, cie, &dw_cie_off, &error);
  }

  dwarf_dealloc_fde_cie_list(dbg, cie_data, cie_element_count, fde_data, fde_element_count);
  return;
}

static void print_cie_instrs(Dwarf_Cie cie, Dwarf_Error *error) {
  int res = DW_DLV_ERROR;
  Dwarf_Unsigned bytes_in_cie = 0;
  Dwarf_Small version = 0;
  char *augmentation = 0;
  Dwarf_Unsigned code_alignment_factor = 0;
  Dwarf_Signed data_alignment_factor = 0;
  Dwarf_Half return_address_register_rule = 0;
  Dwarf_Small *instrp = 0;
  Dwarf_Unsigned instr_len = 0;
  Dwarf_Half offset_size = 0;

  res = dwarf_get_cie_info_b(cie, &bytes_in_cie, &version, &augmentation, &code_alignment_factor, &data_alignment_factor, &return_address_register_rule, &instrp, &instr_len, &offset_size, error);
  if (res != DW_DLV_OK) {
    printf("Unable to get cie info!\n");
    return;
  }
}

static void print_fde_col(Dwarf_Signed k, Dwarf_Addr jsave, Dwarf_Small value_type, Dwarf_Signed offset_relevant, Dwarf_Signed reg_used, Dwarf_Signed offset, Dwarf_Block *block, Dwarf_Addr row_pc, Dwarf_Bool has_more_rows, Dwarf_Addr subsequent_pc) {
  char *type_title = "";
  Dwarf_Unsigned rule_id = k;

  printf(" pc=0x%" DW_PR_DUx, jsave);
  if (row_pc != jsave) {
    printf(" row_pc=0x%" DW_PR_DUx, row_pc);
  }
  printf(" col=%" DW_PR_DSd " ", k);
  switch (value_type) {
  case DW_EXPR_OFFSET:
    type_title = "off";
    goto preg2;
  case DW_EXPR_VAL_OFFSET:
    type_title = "valoff";

  preg2:
    printf("<%s ", type_title);
    if (reg_used == SAME_VAL) {
      printf(" SAME_VAL");
      break;
    } else if (reg_used == INITIAL_VAL) {
      printf(" INITIAL_VAL");
      break;
    }
    print_reg(rule_id);

    printf("=");
    if (offset_relevant == 0) {
      print_reg(reg_used);
      printf(" ");
    } else {
      printf("%02" DW_PR_DSd, offset);
      printf("(");
      print_reg(reg_used);
      printf(") ");
    }
    break;
  case DW_EXPR_EXPRESSION:
    type_title = "expr";
    goto pexp2;
  case DW_EXPR_VAL_EXPRESSION:
    type_title = "valexpr";

  pexp2:
    printf("<%s ", type_title);
    print_reg(rule_id);
    printf("=");
    printf("expr-block-len=%" DW_PR_DUu, block->bl_len);
    {
      char pref[40];

      strcpy(pref, "<");
      strcat(pref, type_title);
      strcat(pref, "bytes:");
      dump_block(pref, block->bl_data, block->bl_len);
      printf("%s", "> \n");
#if 0
            if (glflags.verbose) {
                struct esb_s exprstring;
                esb_constructor(&exprstring);
                get_string_from_locs(dbg,
                    block_ptr,offset,addr_size,
                    offset_size,version,&exprstring);
                printf("<expr:%s>",esb_get_string(&exprstring));
                esb_destructor(&exprstring);
            }
#endif
    }
    break;
  default:
    printf("Internal error in libdwarf, value type %d\n", value_type);
    return;
  }
  printf(" more=%d", has_more_rows);
  printf(" next=0x%" DW_PR_DUx, subsequent_pc);
  printf("%s", "> ");
  printf("\n");
}

static const Dwarf_Block dwblockzero;
static void print_fde_selected_regs(Dwarf_Fde fde) {
  Dwarf_Error oneferr = 0;
  static int selected_cols[] = {1, 3, 5};
  static int selected_cols_count = sizeof(selected_cols) / sizeof(selected_cols[0]);
  Dwarf_Signed k = 0;
  int fres = 0;

  Dwarf_Addr low_pc = 0;
  Dwarf_Unsigned func_length = 0;
  Dwarf_Small *fde_bytes = NULL;
  Dwarf_Unsigned fde_bytes_length = 0;
  Dwarf_Off cie_offset = 0;
  Dwarf_Signed cie_index = 0;
  Dwarf_Off fde_offset = 0;
  Dwarf_Fde curfde = fde;
  Dwarf_Cie cie = 0;
  Dwarf_Addr jsave = 0;
  Dwarf_Addr high_addr = 0;
  Dwarf_Addr next_jsave = 0;
  Dwarf_Bool has_more_rows = 0;
  Dwarf_Addr subsequent_pc = 0;
  Dwarf_Error error = 0;
  int res = 0;

  fres = dwarf_get_fde_range(curfde, &low_pc, &func_length, &fde_bytes, &fde_bytes_length, &cie_offset, &cie_index, &fde_offset, &oneferr);

  if (fres == DW_DLV_ERROR) {
    printf("FAIL: dwarf_get_fde_range err %" DW_PR_DUu " line %d\n", dwarf_errno(oneferr), __LINE__);
    return;
  }
  if (fres == DW_DLV_NO_ENTRY) {
    printf("No fde range data available\n");
    return;
  }
  res = dwarf_get_cie_of_fde(fde, &cie, &error);
  if (res != DW_DLV_OK) {
    printf("Error getting cie from fde\n");
    return;
  }

  high_addr = low_pc + func_length;
  for (jsave = low_pc; next_jsave < high_addr; jsave = next_jsave) {
    next_jsave = jsave + 1;
    printf("\n");
    for (k = 0; k < selected_cols_count; ++k) {
      Dwarf_Unsigned reg = 0;
      Dwarf_Unsigned offset_relevant = 0;
      int fires = 0;
      Dwarf_Small value_type = 0;
      Dwarf_Block block;
      Dwarf_Unsigned offset;
      Dwarf_Addr row_pc = 0;

      block = dwblockzero;
      fires = dwarf_get_fde_info_for_reg3_b(curfde, selected_cols[k], jsave, &value_type, &offset_relevant, &reg, &offset, &block, &row_pc, &has_more_rows, &subsequent_pc, &oneferr);
      if (fires == DW_DLV_ERROR) {
        printf("FAIL: dwarf_get_fde_info_for_reg3_b, "
               "reading reg err %s line %d\n",
               dwarf_errmsg(oneferr), __LINE__);
        return;
      }
      if (fires == DW_DLV_NO_ENTRY) {
        continue;
      }
      print_fde_col(selected_cols[k], jsave, value_type, offset_relevant, reg, offset, &block, row_pc, has_more_rows, subsequent_pc);
      if (has_more_rows) {
        next_jsave = subsequent_pc;
      } else {
        next_jsave = high_addr;
      }
    }
  }
}

static int print_frame_instrs(Dwarf_Debug dbg, Dwarf_Frame_Instr_Head frame_instr_head, Dwarf_Unsigned frame_instr_count, Dwarf_Error *error) {
  Dwarf_Unsigned i = 0;

  printf("\nPrint %" DW_PR_DUu " frame instructions\n", frame_instr_count);
  for (; i < frame_instr_count; ++i) {
    int res = 0;
    Dwarf_Unsigned instr_offset_in_instrs = 0;
    Dwarf_Small cfa_operation = 0;
    const char *fields = 0;
    Dwarf_Unsigned u0 = 0;
    Dwarf_Unsigned u1 = 0;
    Dwarf_Unsigned u2 = 0;
    Dwarf_Signed s0 = 0;
    Dwarf_Signed s1 = 0;
    Dwarf_Block expression_block;
    Dwarf_Unsigned code_alignment_factor = 0;
    Dwarf_Signed data_alignment_factor = 0;
    const char *op_name = 0;

    expression_block = dwblockzero;
    res = dwarf_get_frame_instruction_a(frame_instr_head, i, &instr_offset_in_instrs, &cfa_operation, &fields, &u0, &u1, &u2, &s0, &s1, &code_alignment_factor, &data_alignment_factor, &expression_block, error);
    res = dwarf_get_frame_instruction(frame_instr_head, i, &instr_offset_in_instrs, &cfa_operation, &fields, &u0, &u1, &s0, &s1, &code_alignment_factor, &data_alignment_factor, &expression_block, error);

    if (res != DW_DLV_OK) {
      if (res == DW_DLV_ERROR) {
        printf("ERROR reading frame instruction "
               "%" DW_PR_DUu "\n",
               frame_instr_count);
        if (error) {
          dwarf_dealloc_error(dbg, *error);
          *error = 0;
        }
      } else {
        printf("NO ENTRY reading frame instruction "
               " %" DW_PR_DUu "\n",
               frame_instr_count);
      }
      break;
    }
    dwarf_get_CFA_name(cfa_operation, &op_name);
    printf("[%2" DW_PR_DUu "]  %" DW_PR_DUu " %s ", i, instr_offset_in_instrs, op_name);
    switch (fields[0]) {
    case 'u': {
      if (!fields[1]) {
        printf("%" DW_PR_DUu "\n", u0);
      }
      if (fields[1] == 'c') {
        Dwarf_Unsigned final = u0 * code_alignment_factor;
        printf("%" DW_PR_DUu, final);
#if 0
                if (glflags.verbose) {
                    printf("  (%" DW_PR_DUu " * %" DW_PR_DUu,
                        u0,code_alignment_factor);

                }
#endif
        printf("\n");
      }
    } break;
    case 'r': {
      if (!fields[1]) {
        printf("r%" DW_PR_DUu "\n", u0);
        break;
      }
      if (fields[1] == 'u') {
        if (!fields[2]) {
          printf("%" DW_PR_DUu, u1);
          printf("\n");
          break;
        }
        if (fields[2] == 'd') {
          Dwarf_Signed final = (Dwarf_Signed)u0 * data_alignment_factor;
          printf("%" DW_PR_DUu, final);
          printf("\n");
        }
      }
      if (fields[1] == 'r') {
        printf("r%" DW_PR_DUu "\n", u0);
        printf(" ");
        printf("r%" DW_PR_DUu "\n", u1);
        printf("\n");
      }
      if (fields[1] == 's') {
        if (fields[2] == 'd') {
          Dwarf_Signed final = 0;
          printf("r%" DW_PR_DUu "\n", u0);
          final = s1 * data_alignment_factor;
          printf("%" DW_PR_DSd, final);
          /*  The original did not do this check for 'a'
              but it's harmless to the testing, so added. 2023-06-10 */
          if (fields[3] == 'a') {
            printf(" addrspace %" DW_PR_DUu, u2);
          }
#if 0
                    if (glflags.verbose) {
                        printf("  (%" DW_PR_DSd " * %" DW_PR_DSd,
                            s1,data_alignment_factor);
                    }
#endif
          printf("\n");
        }
      }
      if (fields[1] == 'b') {
        /* rb */
        printf("r%" DW_PR_DUu "\n", u0);
        printf("%" DW_PR_DUu, u0);
        printf(" expr block len %" DW_PR_DUu "\n", expression_block.bl_len);
        dump_block("    ", expression_block.bl_data, (Dwarf_Signed)expression_block.bl_len);
        printf("\n");
#if 0
                if (glflags.verbose) {
                    print_expression(dbg,die,&expression_block,
                        addr_size,offset_size,
                        version);
                }
#endif
      }
    } break;
    case 's': {
      if (fields[1] == 'd') {
        Dwarf_Signed final = s0 * data_alignment_factor;

        printf(" %" DW_PR_DSd, final);
#if 0
                if (glflags.verbose) {
                    printf("  (%" DW_PR_DSd " * %" DW_PR_DSd,
                        s0,data_alignment_factor);
                }
#endif
        printf("\n");
      }
    } break;
    case 'b': {
      if (!fields[1]) {
        printf(" expr block len %" DW_PR_DUu "\n", expression_block.bl_len);
        dump_block("    ", expression_block.bl_data, (Dwarf_Signed)expression_block.bl_len);
        printf("\n");
#if 0
                if (glflags.verbose) {
                    print_expression(dbg,die,&expression_block,
                        addr_size,offset_size,
                        version);
                }
#endif
      }
    } break;
    case 0:
      printf("\n");
      break;
    default:
      printf("UNKNOWN FIELD 0x%x\n", fields[0]);
    }
  }
  return DW_DLV_OK;
}

static void print_fde_instrs(Dwarf_Debug dbg, Dwarf_Fde fde, Dwarf_Error *error) {
  int res;
  Dwarf_Addr lowpc = 0;
  Dwarf_Unsigned func_length = 0;
  Dwarf_Small *fde_bytes;
  Dwarf_Unsigned fde_byte_length = 0;
  Dwarf_Off cie_offset = 0;
  Dwarf_Signed cie_index = 0;
  Dwarf_Off fde_offset = 0;
  Dwarf_Addr arbitrary_addr = 0;
  Dwarf_Addr actual_pc = 0;
  Dwarf_Regtable3 tab3;
  int oldrulecount = 0;
  Dwarf_Small *outinstrs = 0;
  Dwarf_Unsigned instrslen = 0;
  Dwarf_Cie cie = 0;

  res = dwarf_get_fde_range(fde, &lowpc, &func_length, &fde_bytes, &fde_byte_length, &cie_offset, &cie_index, &fde_offset, error);
  if (res != DW_DLV_OK) {
    /*  So nothing clears the error record here,
        the caller does not know the call failed.
        Terrible code, but interesting testcase. */
    printf("Problem getting fde range \n");
    return;
  }

  arbitrary_addr = lowpc + (func_length / 2);
  printf("function low pc 0x%" DW_PR_DUx "  and length 0x%" DW_PR_DUx "  and midpoint addr we choose 0x%" DW_PR_DUx "\n", lowpc, func_length, arbitrary_addr);

  oldrulecount = dwarf_set_frame_rule_table_size(dbg, 1);
  dwarf_set_frame_rule_table_size(dbg, oldrulecount);

  tab3.rt3_reg_table_size = oldrulecount;
  tab3.rt3_rules = (struct Dwarf_Regtable_Entry3_s *)malloc(sizeof(struct Dwarf_Regtable_Entry3_s) * oldrulecount);
  if (!tab3.rt3_rules) {
    printf("Unable to malloc for %d rules\n", oldrulecount);
    return;
  }

  res = dwarf_get_fde_info_for_all_regs3(fde, arbitrary_addr, &tab3, &actual_pc, error);
  printf("function actual addr of row 0x%" DW_PR_DUx "\n", actual_pc);

  if (res != DW_DLV_OK) {
    printf("dwarf_get_fde_info_for_all_regs3 failed!\n");
    free(tab3.rt3_rules);
    return;
  }
  print_regtable(&tab3);

  res = dwarf_get_fde_instr_bytes(fde, &outinstrs, &instrslen, error);
  if (res != DW_DLV_OK) {
    free(tab3.rt3_rules);
    printf("dwarf_get_fde_instr_bytes failed!\n");
    return;
  }
  res = dwarf_get_cie_of_fde(fde, &cie, error);
  if (res != DW_DLV_OK) {
    free(tab3.rt3_rules);
    printf("Error getting cie from fde\n");
    return;
  }

  {
    Dwarf_Frame_Instr_Head frame_instr_head = 0;
    Dwarf_Unsigned frame_instr_count = 0;
    res = dwarf_expand_frame_instructions(cie, outinstrs, instrslen, &frame_instr_head, &frame_instr_count, error);
    if (res != DW_DLV_OK) {
      free(tab3.rt3_rules);
      printf("dwarf_expand_frame_instructions failed!\n");
      return;
    }
    printf("Frame op count: %" DW_PR_DUu "\n", frame_instr_count);
    print_frame_instrs(dbg, frame_instr_head, frame_instr_count, error);

    dwarf_dealloc_frame_instr_head(frame_instr_head);
  }
  free(tab3.rt3_rules);
}

static void print_reg(int r) {
  switch (r) {
  case SAME_VAL:
    printf(" %d SAME_VAL ", r);
    break;
  case UNDEF_VAL:
    printf(" %d UNDEF_VAL ", r);
    break;
  case CFA_VAL:
    printf(" %d (CFA) ", r);
    break;
  default:
    printf(" r%d ", r);
    break;
  }
}

static void print_one_regentry(const char *prefix, struct Dwarf_Regtable_Entry3_s *entry) {
  int is_cfa = !strcmp("cfa", prefix);
  printf("%s ", prefix);
  printf("type: %d %s ", entry->dw_value_type, (entry->dw_value_type == DW_EXPR_OFFSET) ? "DW_EXPR_OFFSET" : (entry->dw_value_type == DW_EXPR_VAL_OFFSET) ? "DW_EXPR_VAL_OFFSET" : (entry->dw_value_type == DW_EXPR_EXPRESSION) ? "DW_EXPR_EXPRESSION" : (entry->dw_value_type == DW_EXPR_VAL_EXPRESSION) ? "DW_EXPR_VAL_EXPRESSION" : "Unknown");
  switch (entry->dw_value_type) {
  case DW_EXPR_OFFSET:
    print_reg(entry->dw_regnum);
    printf(" offset_rel? %d ", entry->dw_offset_relevant);
    if (entry->dw_offset_relevant) {
      printf(" offset  %" DW_PR_DSd " ", entry->dw_offset);
      if (is_cfa) {
        printf("defines cfa value");
      } else {
        printf("address of value is CFA plus signed offset");
      }
      if (!is_cfa && entry->dw_regnum != CFA_VAL) {
        printf(" compiler botch, regnum != CFA_VAL");
      }
    } else {
      printf("value in register");
    }
    break;
  case DW_EXPR_VAL_OFFSET:
    print_reg(entry->dw_regnum);
    printf(" offset  %" DW_PR_DSd " ", entry->dw_offset);
    if (is_cfa) {
      printf("does this make sense? No?");
    } else {
      printf("value at CFA plus signed offset");
    }
    if (!is_cfa && entry->dw_regnum != CFA_VAL) {
      printf(" compiler botch, regnum != CFA_VAL");
    }
    break;
  case DW_EXPR_EXPRESSION:
    print_reg(entry->dw_regnum);
    printf(" offset_rel? %d ", entry->dw_offset_relevant);
    printf(" offset  %" DW_PR_DUu " ", entry->dw_offset);
    printf("Block ptr set? %s ", entry->dw_block.bl_data ? "yes" : "no");
    printf(" Value is at address given by expr val ");
    break;
  case DW_EXPR_VAL_EXPRESSION:
    printf(" expression byte len  %" DW_PR_DUu " ", entry->dw_block.bl_len);
    printf("Block ptr set? %s ", entry->dw_block.bl_data ? "yes" : "no");
    printf(" Value is expr val ");
    if (!entry->dw_block.bl_data) {
      printf("Compiler or libdwarf botch, "
             "NULL block data pointer. ");
    }
    break;
  default:
    break;
  }
  printf("\n");
}

static void print_regtable(Dwarf_Regtable3 *tab3) {
  int r;
  int max = 10;
  if (max > tab3->rt3_reg_table_size) {
    max = tab3->rt3_reg_table_size;
  }
  print_one_regentry("cfa", &tab3->rt3_cfa_rule);

  for (r = 0; r < max; r++) {
    char rn[30];
    snprintf(rn, sizeof(rn), "reg %d", r);
    print_one_regentry(rn, tab3->rt3_rules + r);
  }
}
