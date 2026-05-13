#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h> // Include for uint8_t
#include "/src/libyang/src/validation.h" // Include for lyd_validate_module and related types
#include "/src/libyang/build/libyang/context.h" // Include for ly_ctx_new, ly_ctx_destroy
#include "/src/libyang/build/libyang/tree.h" // Include for lyd_parse_data_mem, lyd_free_all
#include "/src/libyang/src/in.h" // Include for lys_parse_mem
#include "/src/libyang/build/libyang/parser_schema.h" // Include for lys_parse_mem

int LLVMFuzzerTestOneInput_27(const uint8_t *data, size_t size) {
    struct ly_ctx *ctx = NULL;
    struct lyd_node *tree = NULL;
    struct lyd_node *result_tree = NULL;
    const struct lys_module *module = NULL;
    LY_ERR err;

    // Initialize the context
    err = ly_ctx_new(NULL, 0, &ctx);
    if (err != LY_SUCCESS) {
        fprintf(stderr, "Failed to create context\n");
        return 0;
    }

    // Load a module into the context for validation
    err = lys_parse_mem(ctx, "module test {namespace urn:tests:test;prefix t;yang-version 1.1; leaf foo {type string;}}", LYS_IN_YANG, (struct lys_module **)&module);
    if (err != LY_SUCCESS || !module) {
        fprintf(stderr, "Failed to parse module\n");
        ly_ctx_destroy(ctx);
        return 0;
    }

    // Prepare the data for the tree
    char *data_copy = (char *)malloc(size + 1);
    if (!data_copy) {
        ly_ctx_destroy(ctx);
        return 0;
    }
    memcpy(data_copy, data, size);
    data_copy[size] = '\0';

    // Parse the data into a tree
    err = lyd_parse_data_mem(ctx, data_copy, LYD_JSON, 0, LYD_VALIDATE_PRESENT, &tree);
    free(data_copy);

    if (err != LY_SUCCESS) {
        fprintf(stderr, "Failed to parse data\n");
        ly_ctx_destroy(ctx);
        return 0;
    }

    // Validate the module with the tree
    err = lyd_validate_module(&tree, module, 0, &result_tree);
    if (err != LY_SUCCESS) {
        fprintf(stderr, "Validation failed\n");
    }

    // Free resources
    lyd_free_all(tree);
    lyd_free_all(result_tree);
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

    LLVMFuzzerTestOneInput_27(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
