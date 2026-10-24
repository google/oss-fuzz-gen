#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "/src/libyang/src/tree_data.h"

int LLVMFuzzerTestOneInput_14(const uint8_t *data, size_t size) {
    struct ly_ctx *ctx = NULL;
    struct lyd_node *parent = NULL;
    struct lyd_node *new_node = NULL;
    const struct lys_module *module = NULL;
    const char *list_name = "example-list";
    uint32_t options = 0;
    LY_ERR err;

    // Initialize the context
    err = ly_ctx_new(NULL, 0, &ctx);
    if (err != LY_SUCCESS) {
        return 0;
    }

    // Load a module to the context
    module = ly_ctx_load_module(ctx, "example-module", NULL);
    if (!module) {
        ly_ctx_destroy(ctx);
        return 0;
    }

    // Prepare a buffer for the list name
    char *name_buffer = malloc(size + 1);
    if (!name_buffer) {
        ly_ctx_destroy(ctx);
        return 0;
    }
    memcpy(name_buffer, data, size);
    name_buffer[size] = '\0';

    // Call the function under test
    err = lyd_new_list(parent, module, name_buffer, options, &new_node, NULL);

    // Clean up
    lyd_free_all(new_node);
    ly_ctx_destroy(ctx);
    free(name_buffer);

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

    LLVMFuzzerTestOneInput_14(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
