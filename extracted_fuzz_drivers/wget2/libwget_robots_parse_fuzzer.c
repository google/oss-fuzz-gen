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

/*
 * covers code in libwget/robots.c
 */

#include <config.h>

#include <assert.h> // assert
#include <stdint.h> // uint8_t
#include <stdlib.h> // malloc, free
#include <string.h> // memcpy

#include "fuzzer.h"
#include "wget.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  wget_robots *robots;
  char *in = (char *)malloc(size + 1);

  assert(in != NULL);

  // 0 terminate
  memcpy(in, data, size);
  in[size] = 0;

  if (wget_robots_parse(&robots, in, "wget2") == WGET_E_SUCCESS)
    wget_robots_free(&robots);

  free(in);

  return 0;
}
