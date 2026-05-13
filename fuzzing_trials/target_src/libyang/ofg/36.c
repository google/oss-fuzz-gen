#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>  // Include for uint8_t
#include "libyang.h"

int LLVMFuzzerTestOneInput_36(const uint8_t *data, size_t size) {
    struct ly_ctx *ctx = NULL;
    struct lyd_node *node = NULL;
    struct lyd_attr *attr = NULL;
    LY_ERR err;

    // Initialize the context
    err = ly_ctx_new(NULL, 0, &ctx);
    if (err != LY_SUCCESS) {
        fprintf(stderr, "Failed to create context\n");
        return 0;
    }

    // Create a dummy node to attach an attribute
    err = lyd_new_path(NULL, ctx, "/example-module:container", NULL, 0, &node);
    if (err != LY_SUCCESS || !node) {
        fprintf(stderr, "Failed to create node\n");
        ly_ctx_destroy(ctx);
        return 0;
    }

    // Allocate memory for attribute name and value
    char *attr_name = malloc(size + 1);
    char *attr_value = malloc(size + 1);
    if (!attr_name || !attr_value) {
        fprintf(stderr, "Memory allocation failed\n");
        lyd_free_tree(node);
        ly_ctx_destroy(ctx);
        free(attr_name);
        free(attr_value);
        return 0;
    }

    // Copy data to attribute name and value
    memcpy(attr_name, data, size);
    attr_name[size] = '\0';
    memcpy(attr_value, data, size);
    attr_value[size] = '\0';

    // Create a dummy attribute
    err = lyd_new_attr(node, NULL, attr_name, attr_value, &attr);
    if (err != LY_SUCCESS) {
        fprintf(stderr, "Failed to create attribute\n");
    }

    // Call the function-under-test
    lyd_free_attr_single(ctx, attr);

    // Cleanup
    lyd_free_tree(node);
    ly_ctx_destroy(ctx);
    free(attr_name);
    free(attr_value);

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

    LLVMFuzzerTestOneInput_36(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
