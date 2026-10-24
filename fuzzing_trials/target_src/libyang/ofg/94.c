#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "libyang.h"

int LLVMFuzzerTestOneInput_94(const uint8_t *data, size_t size) {
  struct ly_ctx *ctx = NULL;
  struct lys_module *module;
  char *namespace = NULL;
  LY_ERR err;

  // Initialize logging once
  static bool log_initialized = false;
  if (!log_initialized) {
    ly_log_options(0);
    log_initialized = true;
  }

  // Create a new libyang context
  err = ly_ctx_new(NULL, 0, &ctx);
  if (err != LY_SUCCESS) {
    fprintf(stderr, "Failed to create context\n");
    return 0;
  }

  // Allocate memory for the namespace string and copy data into it
  namespace = malloc(size + 1);
  if (namespace == NULL) {
    ly_ctx_destroy(ctx);
    return 0;
  }
  memcpy(namespace, data, size);
  namespace[size] = '\0';

  // Call the function-under-test
  module = ly_ctx_get_module_latest_ns(ctx, namespace);

  // Clean up
  free(namespace);
  ly_ctx_destroy(ctx);

  return 0;
}
#ifdef INC_MAIN
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
int main(int argc, char *argv[])
{
    FILE *f;
    uint8_t *data = NULL;
    long size;

    if(argc < 2)
        exit(0);

    f = fopen(argv[1], "rb");
    if(f == NULL)
        exit(0);

    fseek(f, 0, SEEK_END);

    size = ftell(f);
    rewind(f);

    if(size < 1 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_94(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
