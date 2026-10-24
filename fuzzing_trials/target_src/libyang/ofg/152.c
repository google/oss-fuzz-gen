#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "/src/libyang/src/tree_data.h"
#include "/src/libyang/src/context.h"
#include "/src/libyang/src/tree_schema.h"

int LLVMFuzzerTestOneInput_152(const uint8_t *data, size_t size) {
    struct lyd_node *parent = NULL;
    const struct lys_module *module = NULL;
    const char *name = "test-list";
    const char *key1 = "key1";
    uint32_t options = 0;
    struct lyd_node *new_node = NULL;
    struct ly_ctx *ctx = NULL;
    LY_ERR err;

    // Initialize libyang context
    err = ly_ctx_new(NULL, 0, &ctx);
    if (err != LY_SUCCESS) {
        fprintf(stderr, "Failed to create context\n");
        return 0;
    }

    // Load a module to get a valid lys_module reference
    err = lys_parse_mem(ctx, "module test {namespace urn:test;prefix t;list test-list {key \"key1\"; leaf key1 {type string;}}}", LYS_IN_YANG, &module);
    if (err != LY_SUCCESS || !module) {
        fprintf(stderr, "Failed to parse module\n");
        ly_ctx_destroy(ctx);
        return 0;
    }

    // Ensure data is null-terminated
    char *key2 = malloc(size + 1);
    if (key2 == NULL) {
        ly_ctx_destroy(ctx);
        return 0;
    }
    memcpy(key2, data, size);
    key2[size] = '\0';

    // Call the function-under-test
    err = lyd_new_list2(parent, module, name, key1, options, &new_node);
    if (err != LY_SUCCESS) {
        fprintf(stderr, "lyd_new_list2 failed\n");
    }

    // Clean up
    lyd_free_all(new_node);
    ly_ctx_destroy(ctx);
    free(key2);

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

    LLVMFuzzerTestOneInput_152(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
