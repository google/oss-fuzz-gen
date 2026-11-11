#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "/src/libyang/src/tree_data.h"
#include "/src/libyang/build/libyang/context.h"

int LLVMFuzzerTestOneInput_46(const uint8_t *data, size_t size) {
    struct ly_ctx *ctx = NULL;
    struct lyd_node *parent = NULL;
    struct lyd_node *new_node = NULL;
    const struct lys_module *module = NULL;
    char *module_name = NULL;
    char *value = NULL;
    uint32_t options = 0;
    LY_ERR err;

    // Initialize context
    err = ly_ctx_new(NULL, 0, &ctx);
    if (err != LY_SUCCESS) {
        fprintf(stderr, "Failed to create context\n");
        return 0;
    }

    // Ensure there is enough data to split into module_name and value
    if (size < 2) {
        ly_ctx_destroy(ctx);
        return 0;
    }

    // Split data into module_name and value
    size_t half_size = size / 2;
    module_name = malloc(half_size + 1);
    value = malloc(size - half_size + 1);
    if (!module_name || !value) {
        free(module_name);
        free(value);
        ly_ctx_destroy(ctx);
        return 0;
    }
    memcpy(module_name, data, half_size);
    module_name[half_size] = '\0';
    memcpy(value, data + half_size, size - half_size);
    value[size - half_size] = '\0';

    // Load a module to ensure module is not NULL
    err = lys_parse_mem(ctx, "module test {namespace urn:test;prefix t; leaf leaf1 {type string;}}", LYS_IN_YANG, (struct lys_module **)&module);
    if (err != LY_SUCCESS || !module) {
        free(module_name);
        free(value);
        ly_ctx_destroy(ctx);
        return 0;
    }

    // Call the function-under-test
    lyd_new_term(parent, module, module_name, value, options, &new_node);

    // Clean up
    lyd_free_all(new_node);
    free(module_name);
    free(value);
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

    LLVMFuzzerTestOneInput_46(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
