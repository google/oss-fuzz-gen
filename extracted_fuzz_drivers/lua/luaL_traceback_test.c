/*
 * SPDX-License-Identifier: ISC
 *
 * Copyright 2023, Sergey Bronnikov.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "lauxlib.h"
#include "lua.h"
#include "lualib.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  lua_State *L = luaL_newstate();
  if (L == NULL)
    return 0;

  char *buf = malloc(size + 1);
  if (buf == NULL)
    return 0;
  memcpy(buf, data, size);
  buf[size] = '\0';

  luaL_traceback(L, L, buf, 1);

  free(buf);
  lua_settop(L, 0);
  lua_close(L);

  return 0;
}
