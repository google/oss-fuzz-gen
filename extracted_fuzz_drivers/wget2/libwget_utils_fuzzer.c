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

#include <assert.h> // assert
#include <stdlib.h> // malloc, free
#include <string.h> // memcpy
// #include <unistd.h> // chroot

#include "fuzzer.h"
#include "wget.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  char dst1[1];
  char dst2[2];
  char dst3[3];
  char dst4[4];
  char dst5[8];
  char *dst = (char *)malloc(size * 2 + 1);
  char *data0 = (char *)malloc(size + 1);
  int x = 0; // avoid pure functions to be optimized away

  assert(dst != NULL);
  assert(data0 != NULL);

  // 0-terminate data
  memcpy(data0, data, size);
  data0[size] = 0;

  // some test for code coverage
  x += wget_strcmp(NULL, "");
  x += wget_strcmp("", NULL);
  x += wget_strcmp(NULL, NULL);
  x += wget_strcmp(data0, data0);

  x += wget_strncmp(NULL, "", 0);
  x += wget_strncmp("", NULL, 0);
  x += wget_strncmp(NULL, NULL, 0);
  x += wget_strncmp((char *)data, (char *)data, size);

  x += wget_strcasecmp(NULL, "");
  x += wget_strcasecmp("", NULL);
  x += wget_strcasecmp(NULL, NULL);
  x += wget_strcasecmp(data0, data0);

  x += wget_strncasecmp(NULL, "", 0);
  x += wget_strncasecmp("", NULL, 0);
  x += wget_strncasecmp(NULL, NULL, 0);
  x += wget_strncasecmp((char *)data, (char *)data, size);

  x += wget_strcasecmp_ascii(NULL, "");
  x += wget_strcasecmp_ascii("", NULL);
  x += wget_strcasecmp_ascii(NULL, NULL);
  x += wget_strcasecmp_ascii(data0, data0);

  x += wget_strncasecmp_ascii(NULL, "", 0);
  x += wget_strncasecmp_ascii("", NULL, 0);
  x += wget_strncasecmp_ascii(NULL, NULL, 0);
  x += wget_strncasecmp_ascii((char *)data, (char *)data, size);

  wget_strtolower(NULL);
  wget_strtolower(data0);
  memcpy(data0, (char *)data, size); // restore

  wget_millisleep(-1);
  wget_get_timemillis();

  wget_percent_unescape(data0);
  memcpy(data0, data, size); // restore

  x += wget_match_tail(data0, data0);
  x += wget_match_tail("", data0);
  x += wget_match_tail(data0, "");

  x += wget_match_tail_nocase(data0, data0);
  x += wget_match_tail_nocase("", data0);
  x += wget_match_tail_nocase(data0, "");

  //	if (chroot(".") == 0) {
  char *p;
  if ((p = wget_strnglob("*", 1, 0)))
    wget_free(p);
  //	} else
  //		printf("Failed to chroot\n");

  if (size < 31) {
    char buf[16];
    x += !!wget_human_readable(dst1, sizeof(dst1), (1 << size) - 1);
    x += !!wget_human_readable(buf, sizeof(buf), (1 << size) - 1);
  }

  (void)x; // needed to get rid of bug reported by scan-build

  int w, h;
  wget_get_screen_size(&w, &h);

  wget_memtohex(NULL, 0, NULL, 0);
  wget_memtohex(data, size, dst1, sizeof(dst1));
  wget_memtohex(data, size, dst2, sizeof(dst2));
  wget_memtohex(data, size, dst3, sizeof(dst3));
  wget_memtohex(data, size, dst4, sizeof(dst4));
  wget_memtohex(data, size, dst5, sizeof(dst5));
  wget_memtohex(data, size, dst, size * 2 + 1);

  free(data0);
  free(dst);

  return 0;
}
