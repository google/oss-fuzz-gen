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

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <isc/buffer.h>
#include <isc/util.h>

#include <dns/compress.h>
#include <dns/fixedname.h>
#include <dns/name.h>
#include <dns/qp.h>

#include "fuzz.h"

#include <tests/qp.h>

bool debug = false;

int LLVMFuzzerInitialize(int *argc, char ***argv) {
  UNUSED(argc);
  UNUSED(argv);
  return (0);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  dns_fixedname_t fixedin, fixedout, fixedcmp;
  dns_name_t *namein, *nameout, *namecmp;
  isc_buffer_t buf;
  dns_qpkey_t key, cmp;

  namein = dns_fixedname_initname(&fixedin);
  nameout = dns_fixedname_initname(&fixedout);
  namecmp = dns_fixedname_initname(&fixedcmp);

  isc_buffer_constinit(&buf, data, size);
  isc_buffer_add(&buf, size);
  isc_buffer_setactive(&buf, size);

  CHECK(dns_name_fromwire(namein, &buf, DNS_DECOMPRESS_NEVER, NULL));

  /* verify round-trip conversion of first name */
  size_t keylen = dns_qpkey_fromname(key, namein);
  dns_qpkey_toname(key, keylen, nameout);

  assert(dns_name_equal(namein, nameout));

  /* is there a second name? */
  CHECK(dns_name_fromwire(namecmp, &buf, DNS_DECOMPRESS_NEVER, NULL));

  size_t cmplen = dns_qpkey_fromname(cmp, namecmp);
  size_t len = ISC_MIN(keylen, cmplen);

  int namerel = dns_name_compare(namein, namecmp);
  int keyrel = memcmp(key, cmp, len + 1);

  assert((namerel < 0) == (keyrel < 0));
  assert((namerel == 0) == (keyrel == 0));
  assert((namerel > 0) == (keyrel > 0));

  return (0);
}
