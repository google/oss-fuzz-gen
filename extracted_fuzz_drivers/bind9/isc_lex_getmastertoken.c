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
#include <isc/lex.h>
#include <isc/mem.h>
#include <isc/string.h>
#include <isc/util.h>

#include "fuzz.h"

bool debug = false;

int LLVMFuzzerInitialize(int *argc ISC_ATTR_UNUSED, char ***argv ISC_ATTR_UNUSED);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

static isc_mem_t *mctx = NULL;
static isc_lex_t *lex = NULL;

int LLVMFuzzerInitialize(int *argc ISC_ATTR_UNUSED, char ***argv ISC_ATTR_UNUSED) {
  isc_mem_create(&mctx);
  isc_lex_create(mctx, 1024, &lex);

  return (0);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  isc_buffer_t buf;
  isc_result_t result;
  isc_token_t token;
  isc_tokentype_t expect;
  bool eol;

  if (size < sizeof(expect) + sizeof(eol)) {
    return (0);
  }

  (void)memmove(&expect, data, sizeof(expect));
  data += sizeof(expect);
  size -= sizeof(expect);

  eol = *data != 0;
  data += 1;
  size -= 1;

  isc_buffer_constinit(&buf, data, size);
  isc_buffer_add(&buf, size);
  isc_buffer_setactive(&buf, size);

  CHECK(isc_lex_openbuffer(lex, &buf));

  do {
    result = isc_lex_getmastertoken(lex, &token, expect, eol);
  } while (result == ISC_R_SUCCESS && token.type != isc_tokentype_eof);

  return (0);
}
