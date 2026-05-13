#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libyang.h>  // Corrected header file

int LLVMFuzzerTestOneInput_48(const uint8_t *data, size_t size) {
    struct ly_ctx *ctx = NULL;
    struct lyd_node *tree = NULL;
    const struct lysc_node *schema_node = NULL;
    LY_ERR err;

    // Initialize the libyang context
    err = ly_ctx_new(NULL, 0, &ctx);
    if (err != LY_SUCCESS) {
        fprintf(stderr, "Failed to create context\n");
        return 0;
    }

    // Create a dummy YANG module to ensure the context is not empty
    const char *schema = "module test {namespace urn:test;prefix t;container top {leaf foo {type string;}}}";
    err = lys_parse_mem(ctx, schema, LYS_IN_YANG, NULL);
    if (err != LY_SUCCESS) {
        fprintf(stderr, "Failed to parse schema\n");
        ly_ctx_destroy(ctx);
        return 0;
    }

    // Create a temporary buffer to hold the data
    char *data_buf = (char *)malloc(size + 1);
    if (!data_buf) {
        ly_ctx_destroy(ctx);
        return 0;
    }
    memcpy(data_buf, data, size);
    data_buf[size] = '\0';

    // Parse the input data into a data tree
    lyd_parse_data_mem(ctx, data_buf, LYD_JSON, LYD_PARSE_ONLY, 0, &tree);

    // Call the function-under-test
    if (tree) {
        schema_node = lyd_node_schema(tree);
    }

    // Clean up
    lyd_free_all(tree);
    ly_ctx_destroy(ctx);
    free(data_buf);

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

    LLVMFuzzerTestOneInput_48(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
