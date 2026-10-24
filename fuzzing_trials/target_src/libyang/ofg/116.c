#include <stdio.h>
#include <stdlib.h>
#include "/src/libyang/src/tree_data.h"

int LLVMFuzzerTestOneInput_116(const uint8_t *data, size_t size) {
    struct ly_ctx *ctx = NULL;
    struct lyd_node *parent = NULL;
    struct lyd_node *tree = NULL;
    const struct lys_module *module = NULL;
    const char *value = NULL;
    const char *name = NULL;
    uint32_t value_type = 0;
    uint32_t options = 0;
    LY_ERR err;

    // Initialize libyang context
    err = ly_ctx_new(NULL, 0, &ctx);
    if (err != LY_SUCCESS) {
        fprintf(stderr, "Failed to create context\n");
        return 0;
    }

    // Load a module to get a valid lys_module pointer
    module = ly_ctx_load_module(ctx, "ietf-interfaces", NULL);
    if (!module) {
        fprintf(stderr, "Failed to load module\n");
        ly_ctx_destroy(ctx);
        return 0;
    }

    // Use the data as a string for name and value
    if (size > 0) {
        name = (const char *)data;
        value = (const char *)data;
    }

    // Call the function-under-test
    err = lyd_new_any(parent, module, name, NULL, value, value_type, options, &tree);

    // Cleanup
    lyd_free_all(tree);
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

    LLVMFuzzerTestOneInput_116(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
