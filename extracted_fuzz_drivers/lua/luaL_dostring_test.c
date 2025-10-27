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

  luaL_openlibs(L);

  char *str = malloc(size + 1);
  if (str == NULL)
    return 0;
  memcpy(str, data, size);
  str[size] = '\0';

#ifdef LUAJIT
  /* See https://luajit.org/running.html. */
  luaL_dostring(L, "jit.opt.start('hotloop=1')");
  luaL_dostring(L, "jit.opt.start('hotexit=1')");
  luaL_dostring(L, "jit.opt.start('recunroll=1')");
  luaL_dostring(L, "jit.opt.start('callunroll=1')");
#endif /* LUAJIT */
  luaL_dostring(L, str);

  free(str);
  lua_settop(L, 0);
  lua_close(L);

  return 0;
}
