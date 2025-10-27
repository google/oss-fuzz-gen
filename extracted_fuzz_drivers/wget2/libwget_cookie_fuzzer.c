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

static void cookie_free(void *cookie) {
  if (cookie)
    wget_cookie_free((wget_cookie **)&cookie);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  wget_cookie_db *db, *db2;
  wget_cookie *cookie, *cookie2;
  wget_iri *iri;
  wget_vector *cookies;
  char *in;

  if (size > 1000) // same as max_len = 10000 in .options file
    return 0;

  in = (char *)malloc(size + 1);
  assert(in != NULL);

  // 0 terminate
  memcpy(in, data, size);
  in[size] = 0;

  wget_free(wget_cookie_to_setcookie(NULL));
  wget_cookie_store_cookie(NULL, NULL);
  wget_cookie_db_save(NULL, NULL);
  wget_cookie_db_load(NULL, NULL);
  wget_cookie_create_request_header(NULL, NULL);

  db = wget_cookie_db_init(NULL);
  wget_cookie_set_keep_session_cookies(db, (size & 1) == 0);

  wget_cookie_parse_setcookie(in, &cookie);
  wget_free(wget_cookie_to_setcookie(cookie));

  if (cookie) {
    char fname[64];

    wget_cookie_check_psl(db, cookie);
    iri = wget_iri_parse("x.y", "iso-8859-1");
    wget_cookie_normalize(iri, cookie);

    wget_cookie_store_cookie(db, cookie);

    wget_cookie_parse_setcookie(in, &cookie2);
    cookies = wget_vector_create(4, NULL);
    wget_vector_set_destructor(cookies, cookie_free);
    wget_vector_add(cookies, cookie2);
    wget_cookie_normalize_cookies(iri, cookies);
    wget_cookie_store_cookies(db, cookies);
    wget_http_free_cookies(&cookies);

    wget_free(wget_cookie_create_request_header(db, iri));
    wget_iri_free(&iri);

    // test load & save functions
    wget_snprintf(fname, sizeof(fname), "%d.tmp", getpid());
    wget_cookie_db_save(db, fname);

    db2 = wget_cookie_db_init(NULL);
    wget_cookie_db_load(db2, fname);
    wget_cookie_db_free(&db2);

    unlink(fname);
  }

  wget_cookie_db_load_psl(NULL, NULL);
  wget_cookie_db_load_psl(db, "/dev/null");
  wget_cookie_db_load_psl(db, NULL);

  //	wget_cookie_free(&cookie);
  wget_cookie_db_free(&db);

  free(in);

  return 0;
}
