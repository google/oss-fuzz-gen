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

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size > 10000) // same as max_len = 10000 in .options file
    return 0;

  char *in = (char *)malloc(size + 2);
  assert(in != NULL);

  // 0 terminate
  memcpy(in, data, size);
  in[size] = in[size + 1] = 0;

  wget_iri *base;
  base = wget_iri_parse("http://x.org", "iso-8859-1");
  assert(base != NULL);

  const char *encoding = NULL;
  wget_vector *urls;
  urls = wget_css_get_urls(in, size, base, &encoding);
  wget_vector_free(&urls);
  wget_free((void *)encoding);

  wget_iri_free(&base);

  free(in);

  return 0;
}
