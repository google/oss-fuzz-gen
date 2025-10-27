/*
 * SPDX-License-Identifier: ISC
 *
 * Copyright 2023, Sergey Bronnikov.
 */

#include <assert.h>
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

  char *str = malloc(size + 1);
  if (str == NULL) {
    return 0;
  }
  memcpy(str, data, size);
  str[size] = '\0';

  size_t sz = lua_stringtonumber(L, str);
  if (sz == 0) {
    assert(lua_gettop(L) == 0);
  } else {
    /* assert(sz == size + 1); */
    assert(lua_gettop(L) == 1);
    assert(lua_isnumber(L, -1) == 1);
  }

  free(str);
  lua_settop(L, 0);
  lua_close(L);

  return 0;
}
