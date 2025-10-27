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

#include <isc/attributes.h>
#include <isc/buffer.h>
#include <isc/commandline.h>
#include <isc/lex.h>
#include <isc/mem.h>
#include <isc/string.h>
#include <isc/util.h>

#include <dns/fixedname.h>
#include <dns/name.h>
#include <dns/rdata.h>
#include <dns/rdataclass.h>
#include <dns/rdatatype.h>
#include <dns/result.h>

#include "fuzz.h"

bool debug = false;

int LLVMFuzzerInitialize(int *argc, char ***argv) {
  UNUSED(argc);
  UNUSED(argv);
  return (0);
}

/* following code was copied from named-rrchecker */
isc_lexspecials_t specials = {['('] = 1, [')'] = 1, ['"'] = 1};

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  isc_mem_t *mctx = NULL;
  isc_mem_create(&mctx);

  isc_lex_t *lex = NULL;
  isc_token_t token;

  isc_result_t result;
  unsigned int options = 0;
  dns_rdatatype_t rdtype;
  dns_rdataclass_t rdclass;

  char wiredata[64 * 1024];
  isc_buffer_t wirebuf;
  isc_buffer_init(&wirebuf, wiredata, sizeof(wiredata));

  dns_rdata_t rdata = DNS_RDATA_INIT;
  dns_name_t *name = NULL;

  isc_buffer_t inbuf;
  isc_buffer_constinit(&inbuf, data, size);
  isc_buffer_add(&inbuf, size);
  isc_buffer_setactive(&inbuf, size);

  isc_lex_create(mctx, 256, &lex);

  /*
   * Set up to lex DNS master file.
   */
  isc_lex_setspecials(lex, specials);
  options = ISC_LEXOPT_EOL;
  isc_lex_setcomments(lex, ISC_LEXCOMMENT_DNSMASTERFILE);

  RUNTIME_CHECK(isc_lex_openbuffer(lex, &inbuf) == ISC_R_SUCCESS);

  result = isc_lex_gettoken(lex, options | ISC_LEXOPT_NUMBER, &token);
  if (result != ISC_R_SUCCESS) {
    goto cleanup;
  }
  if (token.type == isc_tokentype_eof) {
    goto cleanup;
  }
  if (token.type == isc_tokentype_eol) {
    goto cleanup;
  }
  /*
   * Get class.
   */
  if (token.type == isc_tokentype_number) {
    if (token.value.as_ulong > 0xffff) {
      goto cleanup;
    }
    rdclass = (dns_rdataclass_t)token.value.as_ulong;
  } else if (token.type == isc_tokentype_string) {
    result = dns_rdataclass_fromtext(&rdclass, &token.value.as_textregion);
    if (result != ISC_R_SUCCESS) {
      goto cleanup;
    }
  } else {
    goto cleanup;
  }
  result = isc_lex_gettoken(lex, options | ISC_LEXOPT_NUMBER, &token);
  if (result != ISC_R_SUCCESS) {
    goto cleanup;
  }
  if (token.type == isc_tokentype_eol) {
    goto cleanup;
  }
  if (token.type == isc_tokentype_eof) {
    goto cleanup;
  }

  /*
   * Get type.
   */
  if (token.type == isc_tokentype_number) {
    if (token.value.as_ulong > 0xffff) {
      goto cleanup;
    }
    rdtype = (dns_rdatatype_t)token.value.as_ulong;
  } else if (token.type == isc_tokentype_string) {
    result = dns_rdatatype_fromtext(&rdtype, &token.value.as_textregion);
    if (result != ISC_R_SUCCESS) {
      goto cleanup;
    }
  } else {
    goto cleanup;
  }

  result = dns_rdata_fromtext(&rdata, rdclass, rdtype, lex, name, 0, mctx, &wirebuf, NULL);
  if (debug) {
    fprintf(stderr, "dns_rdata_fromtext: %s\n", isc_result_totext(result));
  }

cleanup:
  isc_lex_close(lex);
  isc_lex_destroy(&lex);
  isc_mem_destroy(&mctx);
  return (0);
}
