#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <libyang.h> // Correct header for libyang functions and types

int LLVMFuzzerTestOneInput_7(const uint8_t *data, size_t size) {
    struct ly_ctx *ctx = NULL;
    const struct lys_module *module = NULL;
    struct lyd_meta *meta = NULL;
    struct lyd_node *node = NULL;
    char *schema = "module test {namespace urn:tests:test;prefix t;yang-version 1.1;"
                   "leaf name {type string;}}";
    char *data_str = NULL;
    LY_ERR err;

    // Initialize the context
    err = ly_ctx_new(NULL, 0, &ctx);
    if (err != LY_SUCCESS) {
        fprintf(stderr, "Failed to create context\n");
        return 0;
    }

    // Parse the schema
    module = lys_parse_mem(ctx, schema, LYS_IN_YANG, NULL);
    if (!module) {
        fprintf(stderr, "Failed to parse schema\n");
        ly_ctx_destroy(ctx);
        return 0;
    }

    // Prepare data for lyd_parse_data_mem
    data_str = malloc(size + 1);
    if (!data_str) {
        ly_ctx_destroy(ctx);
        return 0;
    }
    memcpy(data_str, data, size);
    data_str[size] = '\0';

    // Parse data to create a data tree
    node = lyd_parse_data_mem(ctx, data_str, LYD_JSON, 0, LYD_VALIDATE_PRESENT, NULL);
    if (!node) {
        free(data_str);
        ly_ctx_destroy(ctx);
        return 0;
    }

    // Call the function-under-test
    meta = lyd_find_meta(node->meta, module, "name");

    // Clean up
    lyd_free_all(node);
    free(data_str);
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

    LLVMFuzzerTestOneInput_7(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
