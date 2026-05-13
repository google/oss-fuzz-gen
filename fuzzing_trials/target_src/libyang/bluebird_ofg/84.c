#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "libyang.h"  // Correct header file for libyang

int LLVMFuzzerTestOneInput_84(const uint8_t *data, size_t size) {
    struct ly_ctx *ctx = NULL;
    struct lyd_node *node = NULL;
    LY_ERR err;

    // Initialize libyang context
    err = ly_ctx_new(NULL, 0, &ctx);
    if (err != LY_SUCCESS) {
        fprintf(stderr, "Failed to create context\n");
        return 0;
    }

    // Create a dummy node to attach the attribute
    const char *schema = "module test {namespace urn:test;prefix t;leaf dummy {type string;}}";
    err = lys_parse_mem(ctx, schema, LYS_IN_YANG, NULL);
    if (err != LY_SUCCESS) {
        fprintf(stderr, "Failed to parse schema\n");
        ly_ctx_destroy(ctx);
        return 0;
    }

    node = lyd_new_path(NULL, ctx, "/test:dummy", NULL, 0, 0);
    if (!node) {
        fprintf(stderr, "Failed to create node\n");
        ly_ctx_destroy(ctx);
        return 0;
    }

    // Ensure size is non-zero before proceeding
    if (size == 0) {
        lyd_free_all(node);
        ly_ctx_destroy(ctx);
        return 0;
    }

    // Prepare attribute name and value
    char *attr_value = malloc(size + 1);
    if (attr_value == NULL) {
        lyd_free_all(node);
        ly_ctx_destroy(ctx);
        return 0;
    }
    memcpy(attr_value, data, size);
    attr_value[size] = '\0';

    // Call the function-under-test
    struct lyd_attr *attr = lyd_new_attr(node, NULL, "attr", attr_value, NULL);
    if (!attr) {
        fprintf(stderr, "Failed to create attribute\n");
    }

    // Clean up
    lyd_free_all(node);
    ly_ctx_destroy(ctx);
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

    LLVMFuzzerTestOneInput_84(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
