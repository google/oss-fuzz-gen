#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "libyang.h"

int LLVMFuzzerTestOneInput_130(const uint8_t *data, size_t size) {
    struct ly_ctx *ctx = NULL;
    struct lyd_node *tree1 = NULL;
    struct lyd_node *tree2 = NULL;
    struct lyd_node *diff = NULL;
    LY_ERR err;

    // Initialize libyang context
    err = ly_ctx_new(NULL, 0, &ctx);
    if (err != LY_SUCCESS) {
        fprintf(stderr, "Failed to create context\n");
        return 0;
    }

    // Load some schemas into the context (example schemas)
    const char *schema_a = "module a {namespace urn:a;prefix a;leaf foo {type string;}}";
    const char *schema_b = "module b {namespace urn:b;prefix b;leaf bar {type string;}}";
    lys_parse_mem(ctx, schema_a, LYS_IN_YANG, NULL);
    lys_parse_mem(ctx, schema_b, LYS_IN_YANG, NULL);

    // Prepare data for tree1 and tree2
    char *data1 = malloc(size + 1);
    if (!data1) {
        ly_ctx_destroy(ctx);
        return 0;
    }
    memcpy(data1, data, size);
    data1[size] = 0;

    char *data2 = malloc(size + 1);
    if (!data2) {
        free(data1);
        ly_ctx_destroy(ctx);
        return 0;
    }
    memcpy(data2, data, size);
    data2[size] = 0;

    // Parse data into trees
    lyd_parse_data_mem(ctx, data1, LYD_JSON, 0, LYD_VALIDATE_PRESENT, &tree1);
    lyd_parse_data_mem(ctx, data2, LYD_JSON, 0, LYD_VALIDATE_PRESENT, &tree2);

    // Call the function-under-test
    lyd_diff_tree(tree1, tree2, 0, &diff);

    // Free resources
    lyd_free_all(tree1);
    lyd_free_all(tree2);
    lyd_free_all(diff);
    ly_ctx_destroy(ctx);
    free(data1);
    free(data2);

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

    LLVMFuzzerTestOneInput_130(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
