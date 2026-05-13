#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "libyang.h"

int LLVMFuzzerTestOneInput_21(const uint8_t *data, size_t size) {
  struct ly_ctx *ctx = NULL;
  const struct lys_module *module = NULL;
  const struct lysp_submodule *submodule = NULL;
  char *module_name = NULL;
  char *revision = NULL;
  LY_ERR err;

  // Initialize libyang context
  err = ly_ctx_new(NULL, 0, &ctx);
  if (err != LY_SUCCESS) {
    fprintf(stderr, "Failed to create context\n");
    return 0;
  }

  // Ensure the data is large enough for module_name and revision
  if (size < 2) {
    ly_ctx_destroy(ctx);
    return 0;
  }

  // Allocate memory for module_name and revision
  module_name = malloc(size / 2 + 1);
  revision = malloc(size / 2 + 1);
  if (!module_name || !revision) {
    free(module_name);
    free(revision);
    ly_ctx_destroy(ctx);
    return 0;
  }

  // Copy data into module_name and revision
  memcpy(module_name, data, size / 2);
  module_name[size / 2] = '\0';
  memcpy(revision, data + size / 2, size / 2);
  revision[size / 2] = '\0';

  // Load a module into the context (using a dummy schema for demonstration)
  const char *dummy_schema = "module dummy {namespace urn:dummy;prefix d;}";
  module = lys_parse_mem(ctx, dummy_schema, LYS_IN_YANG, NULL);

  // Call the function-under-test
  submodule = ly_ctx_get_submodule2(module, module_name, revision);

  // Clean up
  free(module_name);
  free(revision);
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

    LLVMFuzzerTestOneInput_21(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
