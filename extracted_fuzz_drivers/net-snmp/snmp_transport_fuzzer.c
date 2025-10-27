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
#include "../../snmplib/transports/snmpIPBaseDomain.h"
#include "ada_fuzz_header.h"
#include <net-snmp/library/snmpIPXDomain.h>
#include <net-snmp/library/snmpUDPIPv6Domain.h>
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

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
  return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  /*
   * Force the fuzzer to create larger strings as we use
   * a lot of the data.
   */
  if (size < 550) {
    return 0;
  }
  af_gb_init();

  const uint8_t *data2 = data;
  size_t size2 = size;

  netsnmp_ds_set_string(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_APPTYPE, "testprog");

  init_snmp_transport();
  netsnmp_tdomain_init();

  /*
   * Main fuzzing logic
   */
  char *prefix = af_gb_get_null_terminated(&data2, &size2);
  char *fmt_data = af_gb_get_null_terminated(&data2, &size2);
  netsnmp_transport *t2 = NULL;
  if (prefix && fmt_data) {
    free(netsnmp_ipv6_fmtaddr(prefix, t2, fmt_data, strlen(fmt_data)));

    struct sockaddr_in6 addr;
    if (!netsnmp_sockaddr_in6(&addr, prefix, 5123))
      goto cleanup;
  }

  /*
   * Security parsing routines.
   */
  char *udp6_token = af_gb_get_null_terminated(&data2, &size2);
  char *udp6_param = af_gb_get_null_terminated(&data2, &size2);
  if (udp6_token && udp6_param) {
    netsnmp_udp6_parse_security(udp6_token, udp6_param);
  }

  char *udp_token = af_gb_get_null_terminated(&data2, &size2);
  char *udp_param = af_gb_get_null_terminated(&data2, &size2);
  if (udp_token && udp_param) {
    netsnmp_udp_parse_security(udp_token, udp_param);
  }

  struct netsnmp_ep_str ep_str = {};
  char *endpoint = af_gb_get_null_terminated(&data2, &size2);
  if (endpoint && !netsnmp_parse_ep_str(&ep_str, endpoint))
    goto cleanup;

  char *unix_token = af_gb_get_null_terminated(&data2, &size2);
  char *unix_param = af_gb_get_null_terminated(&data2, &size2);
  if (unix_token && unix_param) {
    netsnmp_unix_parse_security(unix_token, unix_param);
  }

  /*
   * Cleanup
   */
  free(ep_str.addr);
cleanup:
  netsnmp_clear_tdomain_list();
  shutdown_snmp_transport();

  af_gb_cleanup();
  return 0;
}
