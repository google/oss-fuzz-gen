/*
 * Copyright(c) 2021 to 2022 ZettaScale Technology and others
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v. 2.0 which is available at
 * http://www.eclipse.org/legal/epl-2.0, or the Eclipse Distribution License
 * v. 1.0 which is available at
 * http://www.eclipse.org/org/documents/edl-v10.php.
 *
 * SPDX-License-Identifier: EPL-2.0 OR BSD-3-Clause
 */

#include <dds/dds.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "dds/ddsi/ddsi_builtin_topic_if.h"
#include "dds/ddsi/ddsi_domaingv.h"
#include "dds/ddsi/ddsi_entity.h"
#include "dds/ddsi/ddsi_entity_index.h"
#include "dds/ddsi/ddsi_iid.h"
#include "dds/ddsi/ddsi_init.h"
#include "dds/ddsi/ddsi_plist.h"
#include "dds/ddsi/ddsi_serdata.h"
#include "dds/ddsi/ddsi_sertype.h"
#include "dds/ddsi/ddsi_tkmap.h"
#include "dds/ddsrt/heap.h"
#include "dds__types.h"
#include "dds__whc.h"
#include "ddsi__addrset.h"
#include "ddsi__radmin.h"
#include "ddsi__receive.h"
#include "ddsi__thread.h"
#include "ddsi__tran.h"
#include "ddsi__transmit.h"
#include "ddsi__vnet.h"
#include "ddsi__xmsg.h"

static struct ddsi_cfgst *cfgst;
static struct ddsi_domaingv gv;
static struct ddsi_config cfg;
static struct ddsi_tran_conn *fakeconn;
static struct ddsi_tran_factory *fakenet;
static struct ddsi_thread_state *thrst;
static struct ddsi_rbufpool *rbpool;

static void null_log_sink(void *varg, const dds_log_data_t *msg) {
  (void)varg;
  (void)msg;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size >= 65536)
    return EXIT_SUCCESS;

  ddsi_iid_init();
  ddsi_thread_states_init();

  // register the main thread, then claim it as spawned by Cyclone because the
  // internal processing has various asserts that it isn't an application thread
  // doing the dirty work
  thrst = ddsi_lookup_thread_state();
  assert(thrst->state == DDSI_THREAD_STATE_LAZILY_CREATED);
  thrst->state = DDSI_THREAD_STATE_ALIVE;
  ddsrt_atomic_stvoidp(&thrst->gv, &gv);

  memset(&gv, 0, sizeof(gv));
  ddsi_config_init_default(&gv.config);
  gv.config.transport_selector = DDSI_TRANS_NONE;

  ddsi_config_prep(&gv, cfgst);
  dds_set_log_sink(null_log_sink, NULL);
  dds_set_trace_sink(null_log_sink, NULL);

  ddsi_init(&gv, NULL);

  ddsi_vnet_init(&gv, "fake", 123);
  fakenet = ddsi_factory_find(&gv, "fake");
  ddsi_factory_create_conn(&fakeconn, fakenet, 0, &(const struct ddsi_tran_qos){.m_purpose = DDSI_TRAN_QOS_XMIT_UC, .m_interface = &gv.interfaces[0]});

  rbpool = ddsi_rbufpool_new(&gv.logconfig, gv.config.rbuf_size, gv.config.rmsg_chunk_size);
  ddsi_rbufpool_setowner(rbpool, ddsrt_thread_self());

  ddsi_guid_prefix_t guidprefix = {0};
  struct ddsi_network_packet_info pktinfo = {0};
  struct ddsi_rmsg *rmsg = ddsi_rmsg_new(rbpool);
  unsigned char *buff = (unsigned char *)DDSI_RMSG_PAYLOAD(rmsg);
  memcpy(buff, data, size);
  ddsi_rmsg_setsize(rmsg, (uint32_t)size);
  ddsi_handle_rtps_message(thrst, &gv, fakeconn, &guidprefix, rbpool, rmsg, size, buff, &pktinfo);
  ddsi_rmsg_commit(rmsg);

  ddsi_fini(&gv);
  ddsi_rbufpool_free(rbpool);
  ddsrt_free(fakeconn);

  // On shutdown there is an expectation that the thread was discovered dynamically.
  // We overrode it in the setup code, we undo it now.
  thrst->state = DDSI_THREAD_STATE_LAZILY_CREATED;
  ddsi_thread_states_fini();
  ddsi_iid_fini();
  return EXIT_SUCCESS;
}
