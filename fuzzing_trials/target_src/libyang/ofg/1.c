#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "libyang.h"

int LLVMFuzzerTestOneInput_1(const uint8_t *data, size_t size) {
    struct ly_ctx *ctx = NULL;
    struct lyd_node *target_tree = NULL;
    struct lyd_node *source_tree = NULL;
    const struct lys_module *module = NULL;
    lyd_diff_cb diff_callback = NULL; // Assuming a simple NULL callback for fuzzing
    void *user_data = NULL;
    uint16_t options = 0;
    LY_ERR err;

    // Initialize libyang context
    err = ly_ctx_new(NULL, 0, &ctx);
    if (err != LY_SUCCESS) {
        fprintf(stderr, "Failed to create context\n");
        return 0;
    }

    // Load a module for testing
    const char *schema = "module test {namespace urn:test;prefix t;yang-version 1.1;"
                         "container data {leaf value {type string;}}}";
    err = lys_parse_mem(ctx, schema, LYS_IN_YANG, &module);
    if (err != LY_SUCCESS || !module) {
        fprintf(stderr, "Failed to parse module\n");
        ly_ctx_destroy(ctx);
        return 0;
    }

    // Create a dummy data tree for testing
    const char *data_str = "<data xmlns=\"urn:test\"><value>test</value></data>";
    err = lyd_parse_data_mem(ctx, data_str, LYD_XML, 0, LYD_VALIDATE_PRESENT, &source_tree);
    if (err != LY_SUCCESS || !source_tree) {
        fprintf(stderr, "Failed to parse data\n");
        ly_ctx_destroy(ctx);
        return 0;
    }

    // Instead of duplicating, reuse source_tree as target_tree for testing
    target_tree = source_tree;

    // Call the function-under-test
    err = lyd_diff_merge_module(&target_tree, source_tree, module, diff_callback, user_data, options);

    // Clean up
    lyd_free_all(source_tree);
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

    LLVMFuzzerTestOneInput_1(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
