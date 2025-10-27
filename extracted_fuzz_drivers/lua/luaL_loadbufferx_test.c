/*
 * SPDX-License-Identifier: ISC
 *
 * Copyright 2023, Sergey Bronnikov.
 */

#include <stdint.h>
#include <stdlib.h> /* malloc, free */
#include <string.h> /* memcpy */

#include "lauxlib.h"
#include "lua.h"
#include "lualib.h"

/*
 * The main purpose of the test is testing Lua frontend (lexer, parser).
 * The test doesn't execute a loaded chunk to be quite fast.
 */

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  lua_State *L = luaL_newstate();
  if (L == NULL)
    return 0;

    /*
     * The string "mode" controls whether the chunk can be text or binary
     * (that is, a precompiled chunk). It may be the string "b" (only binary
     * chunks), "t" (only text chunks), or "bt" (both binary and text). The
     * default is "bt".
     * Lua runtime (at least PUC Rio Lua and LuaJIT) has bytecode and Lua
     * parsers. It is desired to test both parsers, however, in LuaJIT
     * bytecode parser failed with assertion:
     *
     * LuaJIT ASSERT lj_bcread.c:123: bcread_byte: buffer read overflow
     *
     * so in LuaJIT only text mode is used and therefore only text parser is
     * tested.
     */
#ifdef LUAJIT
  const char *mode = "t";
#else
  const char *mode = "bt";
#endif /* LUAJIT */
  luaL_loadbufferx(L, (const char *)data, size, "fuzz", mode);

  lua_settop(L, 0);
  lua_close(L);

  return 0;
}
