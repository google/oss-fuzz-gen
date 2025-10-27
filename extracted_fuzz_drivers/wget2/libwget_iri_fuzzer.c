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

static void test(char *in, size_t len, const char *encoding) {
  wget_iri *base;
  base = wget_iri_parse("http://x.org", encoding);
  assert(base != NULL);

  wget_iri *iri, *iri2;
  iri = wget_iri_parse(in, encoding);
  iri2 = wget_iri_clone(iri);
  wget_iri_free(&iri2);
  iri2 = wget_iri_parse_base(NULL, in, encoding);
  wget_iri_free(&iri2);
  iri2 = wget_iri_parse_base(base, in, encoding);
  int x = wget_iri_compare(iri, iri2);
  wget_iri_free(&iri2);

  wget_buffer buf;
  wget_buffer_init(&buf, NULL, 32);
  wget_buffer_printf(&buf, "%d", x); // use x to avoid optimization (removal of call to wget_iri_compare)

  wget_iri_relative_to_abs(base, (const char *)in, len, &buf);
  wget_iri_escape(in, &buf);
  wget_iri_escape_path(in, &buf);
  wget_iri_escape_query(in, &buf);
  if (iri) {
    if (wget_iri_supported(iri))
      wget_iri_set_scheme(iri, WGET_IRI_SCHEME_HTTPS);
    wget_iri_get_escaped_host(iri, &buf);
    wget_iri_get_escaped_resource(iri, &buf);
    wget_iri_get_path(iri, &buf, encoding);
    wget_iri_get_query_as_filename(iri, &buf, encoding);
    wget_iri_get_basename(iri, &buf, encoding, WGET_IRI_WITH_QUERY);
    wget_iri_get_connection_part(iri, &buf);
  }

  wget_buffer_deinit(&buf);
  wget_iri_free(&iri);
  wget_iri_free(&base);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size > 10000) // same as max_len = 10000 in .options file
    return 0;

  char *in = (char *)malloc(size + 1);
  assert(in != NULL);

  // 0 terminate
  memcpy(in, data, size);
  in[size] = 0;

  // the expression avoids removal of calls to pure functions
  if (wget_iri_isreserved('='))
    wget_iri_set_defaultpage("index.html");

  test(in, size, "iso-8859-1");
  test(in, size, "utf-8");

  free(in);

  return 0;
}
