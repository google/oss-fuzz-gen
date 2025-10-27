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

#ifdef LUAJIT
  /* See https://luajit.org/running.html. */
  luaL_dostring(L, "jit.opt.start('hotloop=1')");
  luaL_dostring(L, "jit.opt.start('hotexit=1')");
  luaL_dostring(L, "jit.opt.start('recunroll=1')");
  luaL_dostring(L, "jit.opt.start('callunroll=1')");
#endif /* LUAJIT */

  int res = luaL_loadbuffer(L, (const char *)data, size, "fuzz");
  if (res == LUA_OK) {
    lua_pcall(L, 0, 0, 0);
  }

  lua_settop(L, 0);
  lua_close(L);

  return 0;
}
