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

#include <fuzzer/FuzzedDataProvider.h>

#if defined(__cplusplus)
extern "C" {
#endif /* defined(__cplusplus) */

#include "lauxlib.h"
#include "lua.h"
#include "lualib.h"

#if defined(__cplusplus)
} /* extern "C" */
#endif /* defined(__cplusplus) */

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider fdp(data, size);

  lua_State *L = luaL_newstate();
  if (L == NULL)
    return 0;

  auto str1 = fdp.ConsumeRandomLengthString(size);
  auto str2 = fdp.ConsumeRandomLengthString(size);
  auto str3 = fdp.ConsumeRandomLengthString(size);
  const char *c_str1 = str1.c_str();
  const char *c_str2 = str2.c_str();
  const char *c_str3 = str3.c_str();
  if (strlen(c_str1) == 0 || strlen(c_str2) == 0 || strlen(c_str3) == 0) {
    lua_settop(L, 0);
    lua_close(L);
    return -1;
  }
  int top = lua_gettop(L);
  luaL_gsub(L, c_str1, c_str2, c_str3);
  /* [-0, +1, m] */
  assert(lua_gettop(L) == top + 1);

  lua_settop(L, 0);
  lua_close(L);

  return 0;
}
