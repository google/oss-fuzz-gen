/* Copyright (c) 2020, Red Hat, Inc.
 *
 * Authors:  Jakub Jelen <jjelen@redhat.com>
 *
 * This code is licensed under the GNU LGPL, version 2.1 or later.
 * See the COPYING file in the top-level directory.
 */

#include <libcacard.h>
#include <simpletlv.h>
#include <stdlib.h>

#include "fuzzer.h"

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  uint8_t *data = (uint8_t *)Data;
  size_t outlen = 0;
  struct simpletlv_member *tlv = NULL;

  tlv = simpletlv_parse(data, Size, &outlen);
  simpletlv_free(tlv, outlen);

  return 0;
}

/* vim: set ts=4 sw=4 tw=0 noet expandtab: */
