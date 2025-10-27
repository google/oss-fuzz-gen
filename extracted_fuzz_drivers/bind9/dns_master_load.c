/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * SPDX-License-Identifier: MPL-2.0
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * See the COPYRIGHT file distributed with this work for additional
 * information regarding copyright ownership.
 */

#include <stdbool.h>
#include <stdlib.h>

#include <isc/buffer.h>
#include <isc/mem.h>
#include <isc/util.h>

#include <dns/callbacks.h>
#include <dns/db.h>
#include <dns/master.h>
#include <dns/types.h>

#include "fuzz.h"

bool debug = false;

int LLVMFuzzerInitialize(int *argc, char ***argv) {
  UNUSED(argc);
  UNUSED(argv);
  return (0);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  isc_buffer_t buf;
  isc_result_t result;
  isc_mem_t *mctx = NULL;

  isc_buffer_constinit(&buf, data, size);
  isc_buffer_add(&buf, size);
  isc_buffer_setactive(&buf, size);

  dns_rdatacallbacks_t callbacks;
  dns_rdatacallbacks_init(&callbacks);
  dns_db_t *db = NULL;

  isc_mem_create(&mctx);
  result = dns_db_create(mctx, "rbt", dns_rootname, dns_dbtype_zone, dns_rdataclass_in, 0, NULL, &db);
  if (result != ISC_R_SUCCESS) {
    return 0;
  }

  result = dns_db_beginload(db, &callbacks);
  if (result != ISC_R_SUCCESS) {
    goto end;
  }

  result = dns_master_loadbuffer(&buf, &db->origin, &db->origin, db->rdclass, DNS_MASTER_ZONE, &callbacks, db->mctx);
  if (debug) {
    fprintf(stderr, "loadbuffer: %s\n", isc_result_totext(result));
  }
  result = dns_db_endload(db, &callbacks);
  if (debug) {
    fprintf(stderr, "endload: %s\n", isc_result_totext(result));
  }

end:
  dns_db_detach(&db);
  isc_mem_destroy(&mctx);
  return (0);
}
