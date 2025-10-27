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
#include <isc/lex.h>
#include <isc/mem.h>
#include <isc/result.h>
#include <isc/util.h>

#include <dns/callbacks.h>
#include <dns/compress.h>
#include <dns/master.h>
#include <dns/rdata.h>
#include <dns/rdatatype.h>

#include "fuzz.h"

bool debug = false;

/*
 * Fuzz input to dns_rdata_fromwire(). Then convert the result
 * to text, back to wire format, to multiline text, and back to wire
 * format again, checking for consistency throughout the sequence.
 */

static isc_mem_t *mctx = NULL;
static isc_lex_t *lex = NULL;

int LLVMFuzzerInitialize(int *argc ISC_ATTR_UNUSED, char ***argv ISC_ATTR_UNUSED) {
  isc_lexspecials_t specials;

  isc_mem_create(&mctx);
  isc_lex_create(mctx, 64, &lex);

  memset(specials, 0, sizeof(specials));
  specials[0] = 1;
  specials['('] = 1;
  specials[')'] = 1;
  specials['"'] = 1;
  isc_lex_setspecials(lex, specials);
  isc_lex_setcomments(lex, ISC_LEXCOMMENT_DNSMASTERFILE);

  return (0);
}

static void nullmsg(dns_rdatacallbacks_t *cb, const char *fmt, ...) {
  va_list args;

  UNUSED(cb);

  if (debug) {
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    fprintf(stderr, "\n");
    va_end(args);
  }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  char totext[64 * 1044 * 4];
  dns_compress_t cctx;
  dns_rdatatype_t rdtype;
  dns_rdataclass_t rdclass;
  dns_rdatatype_t typelist[256] = {1000}; /* unknown */
  dns_rdataclass_t classlist[] = {dns_rdataclass_in, dns_rdataclass_hs, dns_rdataclass_ch, dns_rdataclass_any, 60};
  dns_rdata_t rdata1 = DNS_RDATA_INIT, rdata2 = DNS_RDATA_INIT, rdata3 = DNS_RDATA_INIT;
  dns_rdatacallbacks_t callbacks;
  isc_buffer_t source, target;
  isc_result_t result;
  unsigned char fromtext[1024];
  unsigned char fromwire[1024];
  unsigned char towire[1024];
  unsigned int classes = (sizeof(classlist) / sizeof(classlist[0]));
  unsigned int types = 1, flags, t;

  /*
   * First 2 bytes are used to select type and class.
   * dns_rdata_fromwire() only accepts input up to 2^16-1 octets.
   */
  if (size < 2 || size > 0xffff + 2) {
    return (0);
  }

  /*
   * Append known types to list.
   */
  for (t = 1; t <= 0x10000; t++) {
    char typebuf[256];
    if (dns_rdatatype_ismeta(t)) {
      continue;
    }
    dns_rdatatype_format(t, typebuf, sizeof(typebuf));
    if (strncmp(typebuf, "TYPE", 4) != 0) {
      /* Assert when we need to grow typelist. */
      assert(types < sizeof(typelist) / sizeof(typelist[0]));
      typelist[types++] = t;
    }
  }

  /*
   * Random type and class from a limited set.
   */
  rdtype = typelist[(*data++) % types];
  size--;
  rdclass = classlist[(*data++) % classes];
  size--;

  if (debug) {
    fprintf(stderr, "type=%u, class=%u\n", rdtype, rdclass);
  }

  dns_rdatacallbacks_init(&callbacks);
  callbacks.warn = callbacks.error = nullmsg;

  isc_buffer_constinit(&source, data, size);
  isc_buffer_add(&source, size);
  isc_buffer_setactive(&source, size);

  isc_buffer_init(&target, fromwire, sizeof(fromwire));

  /*
   * Reject invalid rdata. (Disallow decompression as we are
   * reading a packet)
   */
  CHECK(dns_rdata_fromwire(&rdata1, rdclass, rdtype, &source, DNS_DECOMPRESS_NEVER, &target));
  assert(rdata1.length == size);

  /*
   * Convert to text from wire.
   */
  isc_buffer_init(&target, totext, sizeof(totext) - 1);
  result = dns_rdata_totext(&rdata1, NULL, &target);
  assert(result == ISC_R_SUCCESS);

  /*
   * Make debugging easier by NUL terminating.
   */
  totext[isc_buffer_usedlength(&target)] = 0;

  /*
   * Convert to wire from text.
   */
  isc_buffer_constinit(&source, totext, isc_buffer_usedlength(&target));
  isc_buffer_add(&source, isc_buffer_usedlength(&target));
  CHECK(isc_lex_openbuffer(lex, &source));

  isc_buffer_init(&target, fromtext, sizeof(fromtext));
  result = dns_rdata_fromtext(&rdata2, rdclass, rdtype, lex, dns_rootname, 0, mctx, &target, &callbacks);
  if (debug && result != ISC_R_SUCCESS) {
    fprintf(stderr, "'%s'\n", totext);
  }
  assert(result == ISC_R_SUCCESS);
  assert(rdata2.length == size);
  assert(!memcmp(rdata2.data, data, size));

  /*
   * Convert to multi-line text from wire.
   */
  isc_buffer_init(&target, totext, sizeof(totext));
  flags = dns_master_styleflags(&dns_master_style_default);
  result = dns_rdata_tofmttext(&rdata1, dns_rootname, flags, 80 - 32, 4, "\n", &target);
  assert(result == ISC_R_SUCCESS);

  /*
   * Convert to wire from text.
   */
  isc_buffer_constinit(&source, totext, isc_buffer_usedlength(&target));
  isc_buffer_add(&source, isc_buffer_usedlength(&target));
  CHECK(isc_lex_openbuffer(lex, &source));

  isc_buffer_init(&target, fromtext, sizeof(fromtext));
  result = dns_rdata_fromtext(&rdata3, rdclass, rdtype, lex, dns_rootname, 0, mctx, &target, &callbacks);
  assert(result == ISC_R_SUCCESS);
  assert(rdata3.length == size);
  assert(!memcmp(rdata3.data, data, size));

  /*
   * Convert rdata back to wire.
   */
  dns_compress_init(&cctx, mctx, DNS_COMPRESS_DISABLED);
  isc_buffer_init(&target, towire, sizeof(towire));
  result = dns_rdata_towire(&rdata1, &cctx, &target);
  dns_compress_invalidate(&cctx);
  assert(result == ISC_R_SUCCESS);
  assert(target.used == size);
  assert(!memcmp(target.base, data, size));

  return (0);
}
