#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "libyang.h"

int LLVMFuzzerTestOneInput_157(const uint8_t *data, size_t size) {
  struct ly_ctx *ctx = NULL;
  struct lyd_node *tree = NULL;
  struct lyd_node_term *node_term = NULL;
  const struct lyd_leafref_links_rec *links = NULL;
  LY_ERR err;

  // Initialize libyang context
  err = ly_ctx_new(NULL, 0, &ctx);
  if (err != LY_SUCCESS) {
    fprintf(stderr, "Failed to create context\n");
    return 0;
  }

  // Load a basic YANG schema to have a context for parsing data
  const char *schema = "module test {namespace urn:test;prefix t;leaf test-leaf {type string;}}";
  err = lys_parse_mem(ctx, schema, LYS_IN_YANG, NULL);
  if (err != LY_SUCCESS) {
    fprintf(stderr, "Failed to parse schema\n");
    ly_ctx_destroy(ctx);
    return 0;
  }

  // Convert input data to a null-terminated string for parsing
  char *data_str = (char *)malloc(size + 1);
  if (data_str == NULL) {
    ly_ctx_destroy(ctx);
    return 0;
  }
  memcpy(data_str, data, size);
  data_str[size] = '\0';

  // Parse the input data into a libyang data tree
  err = lyd_parse_data_mem(ctx, data_str, LYD_JSON, 0, LYD_VALIDATE_PRESENT, &tree);
  free(data_str);
  if (err != LY_SUCCESS) {
    ly_ctx_destroy(ctx);
    return 0;
  }

  // Assume the first node is a term node for testing purposes
  node_term = (struct lyd_node_term *)tree;

  // Call the function-under-test
  err = lyd_leafref_get_links(node_term, &links);

  // Clean up
  lyd_free_all(tree);
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

    LLVMFuzzerTestOneInput_157(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
