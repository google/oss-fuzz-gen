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

#include <dirent.h> // opendir, readdir
#include <stdint.h> // uint8_t
#include <stdio.h>  // fmemopen
#include <string.h> // strncmp
#include <sys/types.h>

#include "wget.h"

#ifdef __cplusplus
extern "C" {
#endif
#include "../src/wget_options.h"
#include "../src/wget_plugin.h"
#include "../src/wget_testing.h"
#ifdef __cplusplus
}
#endif

#include "fuzzer.h"

static const uint8_t *g_data;
static size_t g_size;

#if defined HAVE_DLFCN_H && defined HAVE_FMEMOPEN
#include <dlfcn.h>
#ifdef RTLD_NEXT /* Not defined e.g. on CygWin */
DIR *opendir(const char *name) {
  DIR *(*libc_opendir)(const char *) = (DIR * (*)(const char *)) dlsym(RTLD_NEXT, "opendir");

  if (config.dont_write)
    return NULL;

  return libc_opendir(name);
  /*
  #ifdef TEST_RUN
          printf("opendir %s\n", name);
          if (!strcmp(name, SRCDIR"/wget_options_fuzzer.in"))
                  return libc_opendir(name);
          if (!strcmp(name, SRCDIR"/wget_options_fuzzer.new"))
                  return libc_opendir(name);
          if (!strcmp(name, SRCDIR"/wget_options_fuzzer.repro"))
                  return libc_opendir(name);
  #else
          if (!strcmp(name, "wget_options_fuzzer.in"))
                  return libc_opendir(name);
          if (!strcmp(name, "wget_options_fuzzer.new"))
                  return libc_opendir(name);
          if (!strcmp(name, "wget_options_fuzzer.repro"))
                  return libc_opendir(name);
  #endif

          return libc_opendir(name);
  */
}

FILE *fopen(const char *pathname, const char *mode) {
  FILE *(*libc_fopen)(const char *, const char *) = (FILE * (*)(const char *, const char *)) dlsym(RTLD_NEXT, "fopen");

  if (config.dont_write) {
    if (!strcmp(pathname, "d41d8cd98f00b204e9800998ecf8428e") && !strcmp(mode, "r"))
      return fmemopen((void *)g_data, g_size, mode);

    //		printf("open %s, %s\n", pathname, mode);
  }

  return libc_fopen(pathname, mode);
}
#endif
#endif

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size > 2048) // same as max_len = 4096 in .options file
    return 0;

  g_data = data;
  g_size = size;

  config.dont_write = 1;

  if (size == 0)
    selftest_options();

// try not to open/write to the file system
#if defined HAVE_DLFCN_H && defined HAVE_FMEMOPEN
  static const char *argv[] = {"x", "-q", "--no-config", "--no-local-db", "--config", "d41d8cd98f00b204e9800998ecf8428e"};
  plugin_db_init();
  enable_testing(); // function in wget2 to prevent unwanted action while testing
  init(sizeof(argv) / sizeof(argv[0]), argv);
  deinit();
  plugin_db_finalize(0);
#endif

  config.dont_write = 0;

  return 0;
}
