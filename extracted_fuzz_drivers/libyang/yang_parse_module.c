#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include "libyang.h"

int LLVMFuzzerTestOneInput(uint8_t const *buf, size_t len) {
  struct lys_module *mod;
  uint8_t *data = NULL;
  struct ly_ctx *ctx = NULL;
  static bool log = false;
  LY_ERR err;

  if (!log) {
    ly_log_options(0);
    log = true;
  }

  err = ly_ctx_new(NULL, 0, &ctx);
  if (err != LY_SUCCESS) {
    fprintf(stderr, "Failed to create new context\n");
    return 0;
  }

  data = malloc(len + 1);
  if (data == NULL) {
    fprintf(stderr, "Out of memory\n");
    return 0;
  }
  memcpy(data, buf, len);
  data[len] = 0;

  lys_parse_mem(ctx, (const char *)data, LYS_IN_YANG, &mod);

  free(data);
  ly_ctx_destroy(ctx);
  return 0;
}
