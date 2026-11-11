#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdio.h>
#include "libyang.h"

int LLVMFuzzerTestOneInput_22(const uint8_t *data, size_t size) {
    struct ly_ctx *ctx = NULL;
    struct lyd_node *node = NULL;
    const char *schema = "module test {namespace urn:test;prefix t;yang-version 1.1;"
                         "leaf test-leaf {type string;}}";
    const char *term_value = "test-value";
    LY_ERR err;

    // Initialize libyang context
    err = ly_ctx_new(NULL, 0, &ctx);
    if (err != LY_SUCCESS) {
        fprintf(stderr, "Failed to create context\n");
        return 0;
    }

    // Parse schema
    err = lys_parse_mem(ctx, schema, LYS_IN_YANG, NULL);
    if (err != LY_SUCCESS) {
        fprintf(stderr, "Failed to parse schema\n");
        ly_ctx_destroy(ctx);
        return 0;
    }

    // Allocate memory for data
    char *input_data = malloc(size + 1);
    if (input_data == NULL) {
        ly_ctx_destroy(ctx);
        return 0;
    }
    memcpy(input_data, data, size);
    input_data[size] = '\0';

    // Parse data into a tree
    err = lyd_parse_data_mem(ctx, input_data, LYD_JSON, 0, LYD_VALIDATE_PRESENT, &node);
    if (err != LY_SUCCESS) {
        fprintf(stderr, "Failed to parse data\n");
        free(input_data);
        ly_ctx_destroy(ctx);
        return 0;
    }

    // Fuzz the function-under-test
    lyd_change_term(node, term_value);

    // Cleanup
    lyd_free_all(node);
    free(input_data);
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

    LLVMFuzzerTestOneInput_22(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
