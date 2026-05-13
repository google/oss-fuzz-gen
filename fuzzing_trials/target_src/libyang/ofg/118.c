#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "libyang.h"

int LLVMFuzzerTestOneInput_118(const uint8_t *data, size_t size) {
    struct ly_ctx *ctx = NULL;
    struct lyd_node *parent = NULL;
    struct lyd_node *new_node = NULL;
    const struct lys_module *module = NULL;
    LY_ERR err;

    // Initialize libyang context
    err = ly_ctx_new(NULL, 0, &ctx);
    if (err != LY_SUCCESS) {
        return 0;
    }

    // Load a YANG module into the context
    const char *schema = "module test {namespace urn:test;prefix t;container parent {leaf child {type string;}}}";
    err = lys_parse_mem(ctx, schema, LYS_IN_YANG, &module);
    if (err != LY_SUCCESS || !module) {
        ly_ctx_destroy(ctx);
        return 0;
    }

    // Create a parent node
    err = lyd_new_inner(NULL, module, "parent", 0, &parent);
    if (err != LY_SUCCESS || !parent) {
        ly_ctx_destroy(ctx);
        return 0;
    }

    // Convert data to a null-terminated string
    char *name = malloc(size + 1);
    if (!name) {
        lyd_free_all(parent);
        ly_ctx_destroy(ctx);
        return 0;
    }
    memcpy(name, data, size);
    name[size] = '\0';

    // Call the function-under-test
    err = lyd_new_inner(parent, module, name, 0, &new_node);

    // Clean up
    free(name);
    lyd_free_all(parent);
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

    LLVMFuzzerTestOneInput_118(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
