#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libyang.h>  // Corrected the header file inclusion

int LLVMFuzzerTestOneInput_113(const uint8_t *data, size_t size) {
    struct ly_ctx *ctx = NULL;
    struct lyd_node *node = NULL;
    LY_ERR err;

    // Initialize libyang context
    err = ly_ctx_new(NULL, 0, &ctx);
    if (err != LY_SUCCESS) {
        fprintf(stderr, "Failed to create libyang context\n");
        return 0;
    }

    // Create a dummy data tree node for testing
    const char *schema = "module test {namespace urn:test;prefix t;container c {leaf l {type string;}}}";
    err = lys_parse_mem(ctx, schema, LYS_IN_YANG, NULL);
    if (err != LY_SUCCESS) {
        ly_ctx_destroy(ctx);
        return 0;
    }

    LY_ERR node_err = lyd_new_path(NULL, ctx, "/test:c/l", "value", 0, &node);
    if (node_err != LY_SUCCESS) {
        ly_ctx_destroy(ctx);
        return 0;
    }

    // Prepare strings for attribute name, value, and module name
    char *attr_name = malloc(size + 1);
    char *attr_value = malloc(size + 1);
    char *module_name = malloc(size + 1);

    if (!attr_name || !attr_value || !module_name) {
        lyd_free_tree(node);
        ly_ctx_destroy(ctx);
        free(attr_name);
        free(attr_value);
        free(module_name);
        return 0;
    }

    memcpy(attr_name, data, size);
    attr_name[size] = '\0';
    memcpy(attr_value, data, size);
    attr_value[size] = '\0';
    memcpy(module_name, data, size);
    module_name[size] = '\0';

    // Call the function-under-test
    struct lyd_attr *attr = NULL;
    lyd_new_attr(node, module_name, attr_name, attr_value, &attr);

    // Clean up
    lyd_free_tree(node);
    ly_ctx_destroy(ctx);
    free(attr_name);
    free(attr_value);
    free(module_name);

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

    LLVMFuzzerTestOneInput_113(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
