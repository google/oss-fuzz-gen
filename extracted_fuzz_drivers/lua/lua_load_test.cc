/*
 * SPDX-License-Identifier: ISC
 *
 * Copyright 2023, Sergey Bronnikov.
 */

#include <assert.h>
#include <string.h>

#if defined(__cplusplus)
extern "C" {
#endif /* defined(__cplusplus) */

#include "lauxlib.h"
#include "lua.h"
#include "lualib.h"

#if defined(__cplusplus)
} /* extern "C" */
#endif /* defined(__cplusplus) */

#include <fuzzer/FuzzedDataProvider.h>

typedef struct {
  FuzzedDataProvider *fdp;
} dt;

static const char *Reader(lua_State *L, void *data, size_t *size) {
  dt *test_data = (dt *)data;
  static char *buf = NULL;

  FuzzedDataProvider *fdp = test_data->fdp;
  uint8_t max_str_size = fdp->ConsumeIntegral<uint8_t>();
  if (fdp->remaining_bytes() < max_str_size)
    return NULL;
  auto str = fdp->ConsumeRandomLengthString(max_str_size);
  *size = str.size();

  free(buf);
  buf = (char *)malloc(*size);
  assert(buf);
  memcpy(buf, str.c_str(), *size);

  return buf;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  lua_State *L = luaL_newstate();
  if (L == NULL)
    return 0;

  luaL_openlibs(L);

  FuzzedDataProvider fdp(data, size);
  dt test_data;
  test_data.fdp = &fdp;

  const char *mode = "t";
#if LUA_VERSION_NUM == 501
  int res = lua_load(L, Reader, &test_data, "libFuzzer");
#else  /* Lua 5.3+ */
  int res = lua_load(L, Reader, &test_data, "libFuzzer", mode);
#endif /* LUA_VERSION_NUM */
  if (res == LUA_OK) {
    lua_pcall(L, 0, 0, 0);
  }

  lua_settop(L, 0);
  lua_close(L);

  return 0;
}
