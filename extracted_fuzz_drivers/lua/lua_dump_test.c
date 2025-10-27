/*
 * SPDX-License-Identifier: ISC
 *
 * Copyright 2023, Sergey Bronnikov.
 */

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "lauxlib.h"
#include "lua.h"

static int Writer(struct lua_State *L, const void *p, size_t size, void *ud) {
  /**
   * We are not interested in produced parts of the binary chunk.
   * Test does not execute a binary chunk because it is focused
   * on a Lua runtime frontend. Thereby, high speed of fuzzing is achieved.
   */

  (void)L;
  (void)p;
  (void)ud;

  /**
   * The writer returns an error code: 0 means no errors; any other value
   * means an error and stops lua_dump from calling the writer again.
   */
  return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  lua_State *L = luaL_newstate();
  assert(L != NULL);

  char *str = malloc(size + 1);
  if (str == NULL)
    return 0;
  memcpy(str, data, size);
  str[size] = '\0';

  if (luaL_loadstring(L, str) != LUA_OK) {
    goto end;
  }

#if LUA_VERSION_NUM < 503
  lua_dump(L, Writer, NULL);
#else  /* Lua 5.3+ */
  lua_dump(L, Writer, NULL, 0);
#endif /* LUA_VERSION_NUM */

end:
  free(str);
  lua_settop(L, 0);
  lua_close(L);

  return 0;
}
