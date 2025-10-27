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

  if (!strcmp(pathname, "ocsp") || !strcmp(pathname, "ocsp_hosts"))
    return fmemopen((void *)g_data, g_size, mode);

  return libc_fopen(pathname, mode);
}
#endif
#endif

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  int revoked;

  if (size > 256) // same as max_len = 256 in .options file
    return 0;

  g_data = data;
  g_size = size;

#if !defined _WIN32 && defined HAVE_FMEMOPEN
  wget_ocsp_db *ocsp_db = wget_ocsp_db_init(NULL, "ocsp");
  wget_ocsp_db_load(ocsp_db);
#else
  wget_ocsp_db *ocsp_db = wget_ocsp_db_init(NULL, NULL);
#endif
  wget_ocsp_hostname_is_valid(ocsp_db, "x.y");
  wget_ocsp_fingerprint_in_cache(ocsp_db, "", &revoked);
  wget_ocsp_db_free(&ocsp_db);

  return 0;
}
