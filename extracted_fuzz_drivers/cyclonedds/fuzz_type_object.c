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

#include "dds/ddsi/ddsi_domaingv.h"
#include "dds/ddsi/ddsi_entity.h"
#include "dds/ddsi/ddsi_entity_index.h"
#include "dds/ddsi/ddsi_iid.h"
#include "dds/ddsi/ddsi_init.h"
#include "dds/ddsi/ddsi_typelib.h"
#include "dds/ddsi/ddsi_typewrap.h"
#include "dds/ddsrt/heap.h"
#include "dds__types.h"
#include "ddsi__thread.h"
#include "ddsi__xt_impl.h"

static struct ddsi_cfgst *cfgst;
static struct ddsi_domaingv gv;
static struct ddsi_thread_state *thrst;

static void null_log_sink(void *varg, const dds_log_data_t *msg) {
  (void)varg;
  (void)msg;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
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

  ddsi_typemap_t *type_map = ddsi_typemap_deser(data, (uint32_t)size);
  if (type_map != NULL) {
    for (uint32_t n = 0; n < type_map->x.identifier_object_pair_complete._length; n++) {
      ddsi_typeid_t *type_id_complete = (ddsi_typeid_t *)&type_map->x.identifier_object_pair_complete._buffer[n].type_identifier;
      ddsi_typeobj_t *type_object_complete = (ddsi_typeobj_t *)&type_map->x.identifier_object_pair_complete._buffer[n].type_object;
      ddsi_typeid_t *type_id_minimal = NULL;
      for (uint32_t i = 0; type_id_minimal == NULL && i < type_map->x.identifier_complete_minimal._length; i++) {
        if (ddsi_typeid_compare_impl(&type_id_complete->x, &type_map->x.identifier_complete_minimal._buffer[i].type_identifier1) == 0)
          type_id_minimal = (ddsi_typeid_t *)&type_map->x.identifier_complete_minimal._buffer[i].type_identifier2;
      }

      if (!ddsi_typeid_is_none(type_id_complete) && !ddsi_typeid_is_none(type_id_minimal)) {
        ddsi_typeinfo_t type_info;
        memset(&type_info, 0, sizeof(type_info));
        type_info.x.minimal.dependent_typeid_count = type_info.x.complete.dependent_typeid_count = (int32_t)type_map->x.identifier_object_pair_complete._length - 1;
        ddsi_typeid_copy_impl(&type_info.x.minimal.typeid_with_size.type_id, &type_id_minimal->x);
        ddsi_typeid_copy_impl(&type_info.x.complete.typeid_with_size.type_id, &type_id_complete->x);

        struct ddsi_type *type;
        dds_return_t ret = ddsi_type_ref_proxy(&gv, &type, &type_info, DDSI_TYPEID_KIND_COMPLETE, NULL);
        if (ret == DDS_RETCODE_OK) {
          assert(type != NULL);
          ddsi_type_add_typeobj(&gv, type, &type_object_complete->x);
          ddsi_type_unref(&gv, type);
        }
        ddsi_typeinfo_fini(&type_info);
      }
    }
    ddsi_typemap_fini(type_map);
    ddsrt_free(type_map);
  }

  ddsi_fini(&gv);

  // On shutdown there is an expectation that the thread was discovered dynamically.
  // We overrode it in the setup code, we undo it now.
  thrst->state = DDSI_THREAD_STATE_LAZILY_CREATED;
  ddsi_thread_states_fini();
  ddsi_iid_fini();
  return EXIT_SUCCESS;
}
