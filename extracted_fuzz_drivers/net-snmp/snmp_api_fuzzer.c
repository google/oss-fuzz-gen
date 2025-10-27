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
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
/* We build with the agent/mibgroup/agentx dir in an -I */
#include <protocol.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#include "ada_fuzz_header.h"

int SecmodInMsg_CB(struct snmp_secmod_incoming_params *sp1) { return SNMPERR_SUCCESS; }

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

  struct snmp_secmod_def *sndef = SNMP_MALLOC_STRUCT(snmp_secmod_def);
  sndef->decode = SecmodInMsg_CB;
  register_sec_mod(-1, "modname", sndef);

  return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  af_gb_init();

  const uint8_t *data2 = data;
  size_t size2 = size;
  netsnmp_pdu *pdu = SNMP_MALLOC_TYPEDEF(netsnmp_pdu);
  netsnmp_session session = {.version = AGENTX_VERSION_1};

  agentx_parse(&session, pdu, NETSNMP_REMOVE_CONST(uint8_t *, data), size);

  // Add a variable with random type and value to the PDU
  char *value = af_gb_get_random_data(&data2, &size2, 20);
  if (value != NULL) {
    value[19] = '\0';
    oid name[] = {2, 1, 0};
    int name_len = OID_LENGTH(name);
    char c = (char)af_get_short(&data2, &size2);
    snmp_add_var(pdu, name, name_len, c, value);
  }

  netsnmp_ds_set_boolean(af_get_int(&data2, &size2), af_get_int(&data2, &size2), af_get_int(&data2, &size2));
  netsnmp_ds_set_boolean(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_REVERSE_ENCODE, af_get_int(&data2, &size2));

  void *cp1 = af_gb_get_null_terminated(&data2, &size2);
  if (cp1 != NULL) {
    // Target snmp_pdu_build
    size_t build_out_length = strlen(cp1);
    snmp_pdu_build(pdu, cp1, &build_out_length);

    // Target snmp_parse
    void *parse_data = af_gb_get_random_data(&data2, &size2, 200);
    if (parse_data != NULL) {
      ((char *)parse_data)[199] = '\0';
    }
    netsnmp_session sess = {};
    sess.contextName = af_gb_get_null_terminated(&data2, &size2);
    if (sess.contextName) {
      sess.contextNameLen = strlen(sess.contextName);
    }
    sess.securityLevel = af_get_int(&data2, &size2);

    pdu->securityName = af_get_null_terminated(&data2, &size2);
    if (pdu->securityName) {
      pdu->securityNameLen = strlen(pdu->securityName);
    }

    snmp_free_pdu(pdu);
    pdu = SNMP_MALLOC_TYPEDEF(netsnmp_pdu);

    sess.version = af_get_int(&data2, &size2);
    if (parse_data != NULL) {
      size_t parse_data_len = strlen(parse_data);
      snmp_parse(NULL, &sess, pdu, parse_data, parse_data_len);
    }

    // Target snmp_build
    u_char *out_pkt = malloc(1000);
    size_t pkt_len = 1000;
    size_t offset = 0;
    snmp_build(&out_pkt, &pkt_len, &offset, &sess, pdu);

    // Target snmp utils
    snmpv3_make_report(pdu, af_get_int(&data2, &size2));
    snmpv3_get_report_type(pdu);
    free(out_pkt);
  }

  /*
   * We forcefully added securityName which will be garbage collected by af_gb_cleanup.
   * This means we have to NULL it out here to avoid a double-free.
   */
  if (pdu != NULL) {
    pdu->securityName = NULL;
    pdu->securityNameLen = 0;
  }

  snmp_free_pdu(pdu);
  af_gb_cleanup();
  return 0;
}
