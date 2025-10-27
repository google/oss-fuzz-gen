/*
 * Copyright (c) 2021, Net-snmp authors
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * * Redistributions of source code must retain the above copyright notice, this
 *   list of conditions and the following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 * * Neither the name of the copyright holder nor the names of its
 *   contributors may be used to endorse or promote products derived from
 *   this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>

#include "ada_fuzz_header.h"

int LLVMFuzzerInitialize(int *argc, char ***argv) {
  if (getenv("NETSNMP_DEBUGGING") != NULL) {
    /*
     * Turn on all debugging, to help understand what
     * bits of the parser are running.
     */
    snmp_enable_stderrlog();
    snmp_set_do_debugging(1);
    debug_register_tokens("");
  }

  netsnmp_init_mib();

  return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  af_gb_init();
  const uint8_t *data2 = data;
  size_t size2 = size;

  oid objid[MAX_OID_LEN];
  size_t objidlen = MAX_OID_LEN;
  netsnmp_variable_list variable = {};

  /*
   * Randomize a set of global variables
   */
  netsnmp_ds_set_boolean(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_NUMERIC_TIMETICKS, af_get_short(&data2, &size2));
  netsnmp_ds_set_boolean(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_QUICKE_PRINT, af_get_short(&data2, &size2));
  netsnmp_ds_set_boolean(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_PRINT_NUMERIC_ENUM, af_get_short(&data2, &size2));
  netsnmp_ds_set_boolean(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_READ_UCD_STYLE_OID, af_get_short(&data2, &size2));
  netsnmp_ds_set_boolean(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_PRINT_BARE_VALUE, af_get_short(&data2, &size2));
  netsnmp_ds_set_boolean(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_DONT_PRINT_UNITS, af_get_short(&data2, &size2));
  netsnmp_ds_set_boolean(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_NO_DISPLAY_HINT, af_get_short(&data2, &size2));
  netsnmp_ds_set_boolean(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_ESCAPE_QUOTES, af_get_short(&data2, &size2));

  /*
   * Create three random strings based on fuzz data
   */
  char *s1 = af_gb_get_null_terminated(&data2, &size2);
  char *s2 = af_gb_get_null_terminated(&data2, &size2);
  char *s3 = af_gb_get_null_terminated(&data2, &size2);
  if (!s1 || !s2 || !s3) {
    af_gb_cleanup();
    return 0;
  }

  objidlen = MAX_OID_LEN;
  if (read_objid(s1, objid, &objidlen) == 0) {
    af_gb_cleanup();
    return 0;
  }

  /*
   * Fuzz print_* functions
   */
  short decider = af_get_short(&data2, &size2);
  switch (decider % 14) {
  case 0: {
    variable.type = ASN_INTEGER;
    long value = 3;
    variable.val.integer = &value;
    variable.val_len = 4;
    variable.next_variable = NULL;
    print_variable(objid, objidlen, &variable);
  } break;
  case 1: {
    variable.type = ASN_IPADDRESS;
    variable.val.string = (u_char *)s2;
    variable.val_len = strlen(s2);
    variable.next_variable = NULL;
    print_variable(objid, objidlen, &variable);
  } break;
  case 2: {
    variable.type = ASN_BIT_STR;
    variable.val.string = (u_char *)s2;
    variable.val_len = strlen(s2);
    variable.next_variable = NULL;
    print_variable(objid, objidlen, &variable);
  } break;
  case 3: {
    variable.type = ASN_OPAQUE;
    variable.val.string = (u_char *)s2;
    variable.val_len = strlen(s2);
    variable.next_variable = NULL;
    print_variable(objid, objidlen, &variable);
  } break;
  case 4: {
    variable.type = ASN_OCTET_STR;
    variable.val.string = (u_char *)s2;
    variable.val_len = strlen(s2);
    variable.next_variable = NULL;
    print_variable(objid, objidlen, &variable);
  } break;
  case 5: {
    variable.type = ASN_GAUGE;
    long value = 3;
    variable.val.integer = &value;
    variable.val_len = 4;
    variable.next_variable = NULL;
    print_variable(objid, objidlen, &variable);
  } break;
  case 6: {
    variable.type = ASN_COUNTER64;
    struct counter64 c64;
    c64.low = 0;
    c64.high = 1;
    variable.val.counter64 = &c64;
    variable.val_len = 1;
    variable.next_variable = NULL;
    print_variable(objid, objidlen, &variable);
  } break;
  case 7: {
    variable.type = ASN_TIMETICKS;
    long value = 3;
    variable.val.integer = &value;
    variable.val_len = 4;
    variable.next_variable = NULL;
    print_variable(objid, objidlen, &variable);
  } break;
  case 8: {
    variable.type = ASN_OBJECT_ID;
    variable.val.objid = (oid *)s2;
    variable.val_len = strlen(s2);
    variable.next_variable = NULL;
    print_variable(objid, objidlen, &variable);
  } break;
  case 9: {
    variable.type = ASN_COUNTER;
    long value = 3;
    variable.val.integer = &value;
    variable.next_variable = NULL;
    print_variable(objid, objidlen, &variable);
  } break;
  case 10: {
    variable.type = ASN_UINTEGER;
    long value = 3;
    variable.val.integer = &value;
    variable.next_variable = NULL;
    print_variable(objid, objidlen, &variable);
  } break;
  case 11: {
    variable.type = ASN_OPAQUE_DOUBLE;
    double value = 3.3;
    variable.val.doubleVal = &value;
    variable.next_variable = NULL;
    print_variable(objid, objidlen, &variable);
  } break;
  case 12: {
    variable.type = ASN_OPAQUE_FLOAT;
    float fVal = 3.3;
    variable.val.floatVal = &fVal;
    variable.next_variable = NULL;
    print_variable(objid, objidlen, &variable);
  } break;
  case 13: {
    variable.type = ASN_NULL;
    variable.next_variable = NULL;
    print_variable(objid, objidlen, &variable);
  } break;
  default:
    break;
  }

  /*
   * Fuzz snprint_* functions
   */
  char *snprint_hints = af_gb_get_null_terminated(&data2, &size2);
  if (!snprint_hints) {
    af_gb_cleanup();
    return 0;
  }
  /*
   * Avoid any p's and n's and s's in hints section, as
   * realloc_* functions will use the hints argument in a sprintf
   * call, which will interpret the variables value as a pointer.
   * Adjusting the fuzzers input-space according to meet the preconditions
   * of these functions.
   */
  for (size_t i = 0; i < strlen(snprint_hints); i++) {
    if (snprint_hints[i] == 'p' || snprint_hints[i] == 'n' || snprint_hints[i] == 's' || snprint_hints[i] == 'S') {
      snprint_hints[i] = 'o';
    }
  }

  variable.type = ASN_INTEGER;
  long value1 = 3;
  variable.val.integer = &value1;
  variable.val_len = 4;
  variable.next_variable = NULL;
  char out_buf[100];
  snprint_integer(out_buf, 100, &variable, NULL, snprint_hints, s3);

  variable.type = ASN_UINTEGER;
  long value2 = 3;
  variable.val.integer = &value2;
  variable.val_len = 4;
  variable.next_variable = NULL;
  char out_buf2[100];
  snprint_uinteger(out_buf2, 100, &variable, NULL, snprint_hints, s3);

  /*
   * Free fuzz data
   */
  af_gb_cleanup();
  return 0;
}
