#include <sys/stat.h>
#include "stdbool.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "libyang.h"

int LLVMFuzzerTestOneInput_9(const uint8_t *data, size_t size) {
    struct ly_ctx *ctx = NULL;
    struct lyd_node *node = NULL;
    struct lyd_node *dup_node = NULL;
    LY_ERR err;
    const char *schema = "module test {namespace urn:test;prefix t;leaf a {type string;}}";
    const char *json_data = "{\"t:a\":\"test\"}";

    // Initialize the context
    err = ly_ctx_new(NULL, 0, &ctx);
    if (err != LY_SUCCESS) {
        fprintf(stderr, "Failed to create context\n");
        return 0;
    }

    // Parse the schema
    err = lys_parse_mem(ctx, schema, LYS_IN_YANG, NULL);
    if (err != LY_SUCCESS) {
        fprintf(stderr, "Failed to parse schema\n");
        ly_ctx_destroy(ctx);
        return 0;
    }

    // Parse the JSON data
    err = lyd_parse_data_mem(ctx, json_data, LYD_JSON, 0, LYD_VALIDATE_PRESENT, &node);
    if (err != LY_SUCCESS) {
        fprintf(stderr, "Failed to parse data\n");
        ly_ctx_destroy(ctx);
        return 0;
    }

    // Call the function-under-test
    err = lyd_dup_single_to_ctx(node, ctx, NULL, 0, &dup_node);
    if (err != LY_SUCCESS) {
        fprintf(stderr, "Failed to duplicate node\n");
    }

    // Clean up
    lyd_free_all(node);
    lyd_free_all(dup_node);
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

    LLVMFuzzerTestOneInput_9(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
