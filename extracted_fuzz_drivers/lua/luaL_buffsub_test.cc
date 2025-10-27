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

  auto str = fdp.ConsumeRandomLengthString(size);
  size_t buf_size = str.length() + 1;
  uint8_t n = fdp.ConsumeIntegralInRange<uint8_t>(0, buf_size);

  luaL_Buffer buf;
  luaL_buffinit(L, &buf);
  luaL_addlstring(&buf, str.c_str(), buf_size);
  luaL_buffsub(&buf, n);
  luaL_pushresult(&buf);

  assert(luaL_bufflen(&buf) == buf_size - n);
  lua_settop(L, 0);
  lua_close(L);

  return 0;
}
