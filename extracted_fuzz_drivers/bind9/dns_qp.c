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
#include <err.h>
#include <stdbool.h>
#include <stdint.h>

#include <isc/random.h>
#include <isc/refcount.h>
#include <isc/rwlock.h>
#include <isc/urcu.h>
#include <isc/util.h>

#include <dns/qp.h>
#include <dns/types.h>

#include "fuzz.h"
#include "qp_p.h"

#include <tests/qp.h>

bool debug = false;

#if 0
#define TRACE(...) warnx(__VA_ARGS__)
#else
#define TRACE(...)
#endif

#if 0
#define ASSERT(p)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      \
  do {                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 \
    warnx("%s:%d: %s (%s)", __func__, __LINE__, #p, (p) ? "OK" : "FAIL");                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              \
    ok = ok && (p);                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    \
  } while (0)
#else
#define ASSERT(p) assert(p)
#endif

static struct {
  uint32_t refcount;
  bool exists;
  uint8_t len;
  dns_qpkey_t key;
  dns_qpkey_t ascii;
} item[256 * 256 / 4];

static void fuzz_attach(void *ctx, void *pval, uint32_t ival) {
  assert(ctx == NULL);
  assert(pval == &item[ival]);
  item[ival].refcount++;
}

static void fuzz_detach(void *ctx, void *pval, uint32_t ival) {
  assert(ctx == NULL);
  assert(pval == &item[ival]);
  item[ival].refcount--;
}

static size_t fuzz_makekey(dns_qpkey_t key, void *ctx, void *pval, uint32_t ival) {
  assert(ctx == NULL);
  assert(pval == &item[ival]);
  memmove(key, item[ival].key, item[ival].len);
  return (item[ival].len);
}

static void fuzz_triename(void *ctx, char *buf, size_t size) {
  assert(ctx == NULL);
  strlcpy(buf, "fuzz", size);
}

const dns_qpmethods_t fuzz_methods = {
    fuzz_attach,
    fuzz_detach,
    fuzz_makekey,
    fuzz_triename,
};

static uint8_t random_byte(void) { return (isc_random_uniform(SHIFT_OFFSET - SHIFT_NOBYTE) + SHIFT_NOBYTE); }

int LLVMFuzzerInitialize(int *argc, char ***argv) {
  UNUSED(argc);
  UNUSED(argv);

  for (size_t i = 0; i < ARRAY_SIZE(item); i++) {
    size_t len = isc_random_uniform(100) + 16;
    item[i].len = len;
    for (size_t off = 0; off < len; off++) {
      item[i].key[off] = random_byte();
    }
    memmove(item[i].ascii, item[i].key, len);
    qp_test_keytoascii(item[i].ascii, len);
  }

  return (0);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  isc_result_t result;

  TRACE("------------------------------------------------");

  isc_mem_t *mctx = NULL;
  isc_mem_create(&mctx);
  isc_mem_setdestroycheck(mctx, true);

  dns_qp_t *qp = NULL;
  dns_qp_create(mctx, &fuzz_methods, NULL, &qp);

  /* avoid overrun */
  size = size & ~1;

  size_t count = 0;

  for (size_t in = 0; in < size; in += 2) {
    size_t what = data[in] + data[in + 1] * 256;
    size_t i = (what / 4) % (count * 2 + 2);
    bool exists = item[i].exists;
    uint32_t refcount = item[i].refcount;
    bool ok = true;
    if (what & 2) {
      void *pval = NULL;
      uint32_t ival = ~0U;
      result = dns_qp_getkey(qp, item[i].key, item[i].len, &pval, &ival);
      TRACE("count %zu get %s %zu >%s<", count, isc_result_toid(result), i, item[i].ascii);
      if (result == ISC_R_SUCCESS) {
        ASSERT(pval == &item[i]);
        ASSERT(ival == i);
        ASSERT(item[i].refcount == 1);
        ASSERT(item[i].exists == true);
      } else if (result == ISC_R_NOTFOUND) {
        ASSERT(pval == NULL);
        ASSERT(ival == ~0U);
        ASSERT(item[i].refcount == 0);
        ASSERT(item[i].exists == false);
      } else {
        UNREACHABLE();
      }
    } else if (what & 1) {
      result = dns_qp_insert(qp, &item[i], i);
      TRACE("count %zu ins %s %zu >%s<", count, isc_result_toid(result), i, item[i].ascii);
      if (result == ISC_R_SUCCESS) {
        item[i].exists = true;
        ASSERT(exists == false);
        ASSERT(refcount == 0);
        ASSERT(item[i].refcount == 1);
        count += 1;
        ASSERT(qp->leaf_count == count);
      } else if (result == ISC_R_EXISTS) {
        ASSERT(exists == true);
        ASSERT(refcount == 1);
        ASSERT(item[i].refcount == 1);
        ASSERT(qp->leaf_count == count);
      } else {
        UNREACHABLE();
      }
    } else {
      result = dns_qp_deletekey(qp, item[i].key, item[i].len, NULL, NULL);
      TRACE("count %zu del %s %zu >%s<", count, isc_result_toid(result), i, item[i].ascii);
      if (result == ISC_R_SUCCESS) {
        item[i].exists = false;
        ASSERT(exists == true);
        ASSERT(refcount == 1);
        ASSERT(item[i].refcount == 0);
        count -= 1;
        ASSERT(qp->leaf_count == count);
      } else if (result == ISC_R_NOTFOUND) {
        ASSERT(exists == false);
        ASSERT(refcount == 0);
        ASSERT(item[i].refcount == 0);
        ASSERT(qp->leaf_count == count);
      } else {
        UNREACHABLE();
      }
    }
    if (!ok) {
      qp_test_dumpqp(qp);
      qp_test_dumptrie(qp);
    }
    assert(ok);
  }

  for (size_t i = 0; i < ARRAY_SIZE(item); i++) {
    assert(item[i].exists == (item[i].refcount != 0));
  }

  dns_qp_destroy(&qp);
  isc_mem_destroy(&mctx);
  isc_mem_checkdestroyed(stderr);

  for (size_t i = 0; i < ARRAY_SIZE(item); i++) {
    item[i].exists = false;
    assert(item[i].refcount == 0);
  }

  return (0);
}
