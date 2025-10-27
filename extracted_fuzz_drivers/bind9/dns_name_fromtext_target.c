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

#include <stddef.h>
#include <stdint.h>

#include <isc/buffer.h>
#include <isc/util.h>

#include <dns/fixedname.h>
#include <dns/name.h>

#include "fuzz.h"

bool debug = false;

int LLVMFuzzerInitialize(int *argc ISC_ATTR_UNUSED, char ***argv ISC_ATTR_UNUSED) { return (0); }

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  isc_buffer_t buf;
  isc_result_t result;
  dns_fixedname_t origin;

  dns_fixedname_init(&origin);

  isc_buffer_constinit(&buf, data, size);
  isc_buffer_add(&buf, size);
  isc_buffer_setactive(&buf, size);

  result = dns_name_fromtext(dns_fixedname_name(&origin), &buf, dns_rootname, 0, NULL);
  if (debug) {
    fprintf(stderr, "dns_name_fromtext: %s\n", isc_result_totext(result));
  }
  return (0);
}
