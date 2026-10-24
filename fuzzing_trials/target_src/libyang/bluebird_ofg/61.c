#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>  // Include for memcpy
#include "libyang.h"  // Corrected include path

int LLVMFuzzerTestOneInput_61(const uint8_t *data, size_t size) {
    struct ly_ctx *ctx = NULL;
    struct lyd_node *original_node = NULL;
    struct lyd_node *parent_node = NULL;
    struct lyd_node *dup_node = NULL;
    LY_ERR err;

    // Initialize libyang context
    err = ly_ctx_new(NULL, 0, &ctx);
    if (err != LY_SUCCESS) {
        fprintf(stderr, "Failed to create context\n");
        return 0;
    }

    // Create a dummy schema for testing
    const char *schema = "module test {namespace urn:test;prefix t;leaf name {type string;}}";
    err = lys_parse_mem(ctx, schema, LYS_IN_YANG, NULL);
    if (err != LY_SUCCESS) {
        fprintf(stderr, "Failed to parse schema\n");
        ly_ctx_destroy(ctx);
        return 0;
    }

    // Check if the input data is non-empty and starts with '<' for XML format
    if (size == 0 || data[0] != '<') {
        ly_ctx_destroy(ctx);
        return 0;
    }

    // Ensure the data is null-terminated before parsing
    char *data_copy = (char *)malloc(size + 1);
    if (!data_copy) {
        ly_ctx_destroy(ctx);
        return 0;
    }
    memcpy(data_copy, data, size);
    data_copy[size] = '\0';

    // Create a dummy data tree for testing using the input data
    // Begin mutation: Producer.REPLACE_ARG_MUTATOR - Replaced argument 4 of lyd_parse_data_mem
    err = lyd_parse_data_mem(ctx, data_copy, LYD_XML, 0, size, &original_node);
    // End mutation: Producer.REPLACE_ARG_MUTATOR
    free(data_copy);  // Free the copied data after use
    if (err != LY_SUCCESS) {
        fprintf(stderr, "Failed to parse data\n");
        ly_ctx_destroy(ctx);
        return 0;
    }

    // Call the function-under-test
    // Begin mutation: Producer.REPLACE_FUNC_MUTATOR - Replaced function lyd_dup_single with lyd_dup_siblings
    err = lyd_dup_siblings(original_node, parent_node, 0, &dup_node);
    // End mutation: Producer.REPLACE_FUNC_MUTATOR
    if (err != LY_SUCCESS) {
        fprintf(stderr, "lyd_dup_single failed\n");
    }

    // Clean up
    lyd_free_all(original_node);
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

    LLVMFuzzerTestOneInput_61(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
