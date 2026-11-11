#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include "/src/libyang/src/validation.h"
#include "/src/libyang/build/libyang/tree.h"
#include "/src/libyang/build/libyang/context.h"
#include "/src/libyang/build/libyang/parser_schema.h"
#include "/src/libyang/build/libyang/parser_data.h"

int LLVMFuzzerTestOneInput_32(const uint8_t *data, size_t size) {
    struct ly_ctx *ctx = NULL;
    struct lyd_node *node = NULL;
    const struct lys_module *module = NULL;
    LY_ERR err;
    uint32_t options = 0;

    // Initialize the libyang context
    err = ly_ctx_new(NULL, 0, &ctx);
    if (err != LY_SUCCESS) {
        fprintf(stderr, "Failed to create context\n");
        return 0;
    }

    // Parse a sample YANG schema to get a module
    const char *schema = "module example {namespace \"urn:example\"; prefix ex; leaf foo {type string;}}";
    err = lys_parse_mem(ctx, schema, LYS_IN_YANG, &module);
    if (err != LY_SUCCESS || !module) {
        fprintf(stderr, "Failed to parse module\n");
        ly_ctx_destroy(ctx);
        return 0;
    }

    // Parse the input data as a JSON data tree
    char *input_data = malloc(size + 1);
    if (!input_data) {
        ly_ctx_destroy(ctx);
        return 0;
    }
    memcpy(input_data, data, size);
    input_data[size] = '\0';

    err = lyd_parse_data_mem(ctx, input_data, LYD_JSON, 0, 0, &node);
    free(input_data);

    if (err != LY_SUCCESS || !node) {
        fprintf(stderr, "Failed to parse data\n");
        ly_ctx_destroy(ctx);
        return 0;
    }

    // Call the function-under-test
    err = lyd_validate_module_final(node, module, options);

    // Clean up
    lyd_free_all(node);
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

    LLVMFuzzerTestOneInput_32(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
