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
#include "ada_fuzz_header.h"
#include <net-snmp/agent/net-snmp-agent-includes.h>
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <unistd.h>

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

  setenv("MIBDIRS", "/tmp/", 1);
  return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  af_gb_init();

  /*
   * Extract the fuzz data. We do this early to avoid overhead
   * from initializing the agent and then having to exit due to
   * limited fuzz data.
   */
  char *mib_file_data = af_gb_get_null_terminated(&data, &size);
  char *pdu1_content = af_gb_get_null_terminated(&data, &size);
  char *pdu2_content = af_gb_get_null_terminated(&data, &size);
  char *pdu3_content = af_gb_get_null_terminated(&data, &size);
  char *pdu4_content = af_gb_get_null_terminated(&data, &size);

  char *pdu_arrs[4] = {pdu1_content, pdu2_content, pdu3_content, pdu4_content};
  if (mib_file_data != NULL && pdu1_content != NULL && pdu2_content != NULL && pdu3_content != NULL && pdu4_content != NULL) {
    /*
     * Create a file with random data from the fuzzer and
     * add it as a mib file.
     */
    char filename[256];
    sprintf(filename, "/tmp/libfuzzer.%d", getpid());
    FILE *fp = fopen(filename, "wb");
    if (!fp) {
      af_gb_cleanup();
      return 0;
    }
    fwrite(mib_file_data, strlen(mib_file_data), 1, fp);
    fclose(fp);

    init_agent("snmpd");
    add_mibfile(filename, "not-used");

    init_snmp("snmpd");
    char *no_smux = strdup("!smux");
    add_to_init_list(no_smux);
    init_master_agent();

    /*
     * Handle 4 PDUs initialised based on fuzzer data
     */
    for (int i = 0; i < 4; i++) {
      /*
       * Create a PDU based on parsing fuzz data
       */
      size_t bytes_remaining = strlen(pdu_arrs[i]);
      netsnmp_pdu *pdu = SNMP_MALLOC_TYPEDEF(netsnmp_pdu);
      snmp_pdu_parse(pdu, (unsigned char *)pdu_arrs[i], &bytes_remaining);
      pdu->flags |= UCD_MSG_FLAG_ALWAYS_IN_VIEW;

      /*
       * Create a agent snmp session and handle the snmp packet
       */
      netsnmp_session sess = {};
      netsnmp_agent_session *vals = init_agent_snmp_session(&sess, pdu);
      handle_snmp_packet(1, &sess, 0, pdu, vals);
      snmp_free_pdu(pdu);
    }

    shutdown_master_agent();
    snmp_shutdown("snmpd");
    shutdown_agent();

    /*
     * Cleanup the file
     */
    unlink(filename);
    free(no_smux);
  }

  af_gb_cleanup();
  return 0;
}
