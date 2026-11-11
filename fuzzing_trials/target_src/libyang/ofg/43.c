#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "libyang.h"

int LLVMFuzzerTestOneInput_43(const uint8_t *data, size_t size) {
    struct lyd_node *sibling = NULL;
    struct lysc_node *schema_node = NULL;
    struct lyd_node *result = NULL;
    LY_ERR err;

    // Create a context
    struct ly_ctx *ctx = NULL;
    err = ly_ctx_new(NULL, 0, &ctx);
    if (err != LY_SUCCESS) {
        fprintf(stderr, "Failed to create context\n");
        return 0;
    }

    // Create a dummy schema for testing
    const char *schema = "module test {namespace urn:test;prefix t;leaf test-leaf {type string;}}";
    err = lys_parse_mem(ctx, schema, LYS_IN_YANG, NULL);
    if (err != LY_SUCCESS) {
        fprintf(stderr, "Failed to parse schema\n");
        ly_ctx_destroy(ctx);
        return 0;
    }

    // Use the first schema node from the context for testing
    schema_node = (struct lysc_node *)lys_find_path(ctx, NULL, "/test:test-leaf", 0);
    if (!schema_node) {
        fprintf(stderr, "Failed to find schema node\n");
        ly_ctx_destroy(ctx);
        return 0;
    }

    // Parse the fuzzing input as XML data
    char *data_str = malloc(size + 1);
    if (!data_str) {
        fprintf(stderr, "Failed to allocate memory\n");
        ly_ctx_destroy(ctx);
        return 0;
    }
    memcpy(data_str, data, size);
    data_str[size] = '\0';

    err = lyd_parse_data_mem(ctx, data_str, LYD_XML, 0, LYD_VALIDATE_PRESENT, &sibling);
    if (err != LY_SUCCESS) {
        fprintf(stderr, "Failed to parse fuzzing input as data\n");
        free(data_str);
        ly_ctx_destroy(ctx);
        return 0;
    }

    // Call the function-under-test
    err = lyd_find_sibling_val(sibling, schema_node, data_str, 0, &result);

    // Clean up
    free(data_str);
    lyd_free_all(sibling);
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

    LLVMFuzzerTestOneInput_43(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
