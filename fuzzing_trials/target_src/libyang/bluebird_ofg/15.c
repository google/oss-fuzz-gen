#include <string.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include "/src/libyang/src/tree_data.h" // Include the correct path for tree_data.h
#include "/src/libyang/src/context.h"   // Include context.h for ly_ctx_new and ly_ctx_destroy
#include "/src/libyang/src/tree_schema.h" // Include tree_schema.h for lys_parse_mem
#include "/src/libyang/src/parser_schema.h" // Include parser_schema.h for lys_parse_mem

int LLVMFuzzerTestOneInput_15(const uint8_t *data, size_t size) {
    struct ly_ctx *ctx = NULL;
    struct lyd_node *parent = NULL;
    struct lys_module *module = NULL;
    struct lyd_node *new_node = NULL;
    const char *list_name = "example-list";
    const void *keys[1] = {NULL};
    uint32_t key_count = 1;
    uint32_t options = 0;
    LY_ERR err;

    // Initialize libyang context
    err = ly_ctx_new(NULL, 0, &ctx);
    if (err != LY_SUCCESS) {
        fprintf(stderr, "Failed to create context\n");
        return 0;
    }

    // Load a module to get a valid lys_module pointer
    err = lys_parse_mem(ctx, "module example {namespace urn:example; prefix ex; list example-list {key \"key1\"; leaf key1 {type string;}}}", LYS_IN_YANG, &module);
    if (err != LY_SUCCESS || !module) {
        fprintf(stderr, "Failed to parse module\n");
        ly_ctx_destroy(ctx);
        return 0;
    }

    // Use the input data as a key value
    if (size > 0) {
        keys[0] = (const void *)data;
    } else {
        keys[0] = "default-key";
    }

    // Call the function-under-test
    err = lyd_new_list3(parent, module, list_name, keys, &key_count, options, &new_node);
    if (err != LY_SUCCESS) {
        fprintf(stderr, "lyd_new_list3 failed\n");
    }

    // Cleanup
    lyd_free_all(new_node);
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

    LLVMFuzzerTestOneInput_15(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
