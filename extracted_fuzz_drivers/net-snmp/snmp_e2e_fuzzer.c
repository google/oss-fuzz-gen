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
#include <fcntl.h>
#include <net-snmp/agent/mib_modules.h>
#include <net-snmp/agent/snmp_agent.h>
#include <net-snmp/agent/snmp_vars.h>
#include <net-snmp/library/large_fd_set.h>
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define FAKE_FD 3

const void *recv_data;
int recv_datalen;

int snmpfuzz_recv(netsnmp_transport *t, void *buf, int bufsiz, void **opaque, int *opaque_len) {
  if (bufsiz > recv_datalen) {
    memcpy(buf, recv_data, recv_datalen);
    return recv_datalen;
  } else {
    return -1;
  }
}

static int snmpfuzz_callback(int op, netsnmp_session *sess, int reqid, netsnmp_pdu *pdu, void *magic) {
  /*
   * We leave this empty for now
   */
  return 0;
}

void fuzz_fake_pcap(const u_char *buf, size_t len) {
  netsnmp_large_fd_set lfdset;

  recv_data = buf;
  recv_datalen = len;

  netsnmp_large_fd_set_init(&lfdset, FD_SETSIZE);
  netsnmp_large_fd_setfd(FAKE_FD, &lfdset);
  snmp_read2(&lfdset);
  netsnmp_large_fd_set_cleanup(&lfdset);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  netsnmp_session *ss;
  netsnmp_transport *transport;

  u_char *fuzz_buf = malloc(size + 1);
  memcpy(fuzz_buf, data, size);
  fuzz_buf[size] = '\0';

  ss = SNMP_MALLOC_TYPEDEF(netsnmp_session);

  /*
   * We allocate with malloc to avoid constants
   */
  char **fake_argv = malloc(sizeof(char *) * 3);
  fake_argv[0] = strdup("snmp_e2e_fuzzer");
  fake_argv[1] = strdup("-Dall");
  fake_argv[2] = strdup("localhost");

  snmp_parse_args(3, fake_argv, ss, "", NULL);

  transport = SNMP_MALLOC_TYPEDEF(netsnmp_transport);
  transport->sock = FAKE_FD;
  transport->f_recv = snmpfuzz_recv;

  ss->callback = snmpfuzz_callback;
  ss->callback_magic = (void *)NULL;
  ss->securityModel = SNMP_SEC_MODEL_USM;
  create_user_from_session(ss);

  /*
   * Use snmp_add() to specify transport explicitly
   */
  snmp_add(ss, transport, NULL, NULL);

  fuzz_fake_pcap(fuzz_buf, size);

  snmp_close(ss);
  /* To do: register session 'ss' properly and remove the call below. */
  netsnmp_cleanup_session(ss);
  free(ss);
  free(fuzz_buf);

  free(fake_argv[0]);
  free(fake_argv[1]);
  free(fake_argv[2]);
  free(fake_argv);

  return 0;
}
