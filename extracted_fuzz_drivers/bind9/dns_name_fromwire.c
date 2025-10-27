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
#include <stdlib.h>
#include <unistd.h>

#include <isc/ascii.h>
#include <isc/buffer.h>
#include <isc/util.h>

#include <dns/compress.h>
#include <dns/fixedname.h>
#include <dns/name.h>

#include "fuzz.h"
#include "old.h"

bool debug = false;

int LLVMFuzzerInitialize(int *argc ISC_ATTR_UNUSED, char ***argv ISC_ATTR_UNUSED) { return (0); }

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  isc_result_t new_result;
  isc_result_t old_result;
  dns_fixedname_t new_fixed;
  dns_fixedname_t old_fixed;
  dns_name_t *new_name = dns_fixedname_initname(&new_fixed);
  dns_name_t *old_name = dns_fixedname_initname(&old_fixed);
  uint8_t *new_offsets;
  uint8_t *old_offsets;
  dns_decompress_t dctx = DNS_DECOMPRESS_PERMITTED;
  isc_buffer_t new_buf;
  isc_buffer_t old_buf;

  /*
   * Output buffers may be partially used or undersized.
   */
  if (size > 0) {
    uint8_t add = *data++;
    size--;
    isc_buffer_add(&new_fixed.buffer, add);
    isc_buffer_add(&old_fixed.buffer, add);
  }

  /*
   * timeout faster if we hit a pointer loop
   */
  alarm(1);

  /*
   * We shift forward by half the input data to make an area
   * that pointers can refer back to.
   */

  isc_buffer_constinit(&new_buf, data, size);
  isc_buffer_add(&new_buf, size);
  isc_buffer_setactive(&new_buf, size);
  isc_buffer_forward(&new_buf, size / 2);
  new_result = dns_name_fromwire(new_name, &new_buf, dctx, NULL);

  isc_buffer_constinit(&old_buf, data, size);
  isc_buffer_add(&old_buf, size);
  isc_buffer_setactive(&old_buf, size);
  isc_buffer_forward(&old_buf, size / 2);
  old_result = old_name_fromwire(old_name, &old_buf, dctx, 0, NULL);

  REQUIRE(new_result == old_result);
  REQUIRE(dns_name_equal(new_name, old_name));
  REQUIRE(new_name->labels == old_name->labels);

  new_offsets = new_name->offsets;
  old_offsets = old_name->offsets;
  REQUIRE(new_offsets != NULL && old_offsets != NULL);
  REQUIRE(memcmp(new_offsets, old_offsets, old_name->labels) == 0);

  REQUIRE(new_fixed.buffer.current == old_fixed.buffer.current);
  REQUIRE(new_fixed.buffer.active == old_fixed.buffer.active);
  REQUIRE(new_fixed.buffer.used == old_fixed.buffer.used);
  REQUIRE(new_fixed.buffer.length == old_fixed.buffer.length);

  REQUIRE(new_buf.base == old_buf.base);
  REQUIRE(new_buf.current == old_buf.current);
  REQUIRE(new_buf.active == old_buf.active);
  REQUIRE(new_buf.used == old_buf.used);
  REQUIRE(new_buf.length == old_buf.length);

  return (0);
}
