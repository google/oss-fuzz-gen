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

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "fuzzer.h"
#include "wget.h"

static const uint8_t *g_data;
static size_t g_size;

#if defined HAVE_DLFCN_H && defined HAVE_FMEMOPEN
#include <dlfcn.h>
#ifdef RTLD_NEXT /* Not defined e.g. on CygWin */
FILE *fopen(const char *pathname, const char *mode) {
  FILE *(*libc_fopen)(const char *, const char *) = (FILE * (*)(const char *, const char *)) dlsym(RTLD_NEXT, "fopen");

  if (!strcmp(pathname, "tls"))
    return fmemopen((void *)g_data, g_size, mode);

  return libc_fopen(pathname, mode);
}
#endif
#endif

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  void *p;
  size_t len;

  if (size > 256) // same as max_len = 256 in .options file
    return 0;

  g_data = data;
  g_size = size;

  wget_tls_session_db *tlssess_db = wget_tls_session_db_init(NULL);
#if !defined _WIN32 && defined HAVE_FMEMOPEN
  wget_tls_session_db_load(tlssess_db, "tls");
#endif
  if (wget_tls_session_get(tlssess_db, "x.y", &p, &len) == 0)
    wget_free(p);
  wget_tls_session_db_free(&tlssess_db);

  return 0;
}
