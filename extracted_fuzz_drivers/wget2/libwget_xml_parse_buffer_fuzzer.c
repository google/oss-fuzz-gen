/*
 * Copyright (c) 2017-2024 Free Software Foundation, Inc.
 *
 * This file is part of libwget.
 *
 * Libwget is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Libwget is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with libwget.  If not, see <https://www.gnu.org/licenses/>.
 */

#include <config.h>

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "fuzzer.h"
#include "wget.h"

static void _cb(WGET_GCC_UNUSED void *context, WGET_GCC_UNUSED int flags, WGET_GCC_UNUSED const char *tag, WGET_GCC_UNUSED const char *attr, WGET_GCC_UNUSED const char *val, WGET_GCC_UNUSED size_t len, WGET_GCC_UNUSED size_t pos) {}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size > 10000) // same as max_len = 10000 in .options file
    return 0;

  char *in = (char *)malloc(size + 1);

  assert(in != NULL);

  // 0 terminate
  memcpy(in, data, size);
  in[size] = 0;

  wget_xml_parse_buffer(in, NULL, NULL, 0);
  wget_xml_parse_buffer(in, _cb, NULL, XML_HINT_REMOVE_EMPTY_CONTENT);
  wget_html_parse_buffer(in, _cb, NULL, 0);
  wget_html_parse_buffer(in, _cb, NULL, XML_HINT_REMOVE_EMPTY_CONTENT);

  free(in);

  wget_html_parse_file("/dev/null", NULL, NULL, 0);

  freopen("/dev/null", "r", stdin);
  wget_html_parse_file("-", NULL, NULL, 0);

  return 0;
}
