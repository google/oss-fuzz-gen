#include <stdio.h>
#include <stdlib.h>
#include <string.h>  // Include for memcpy
#include <stdint.h>  // Include for uint8_t
#include <libyang.h>  // Correct header file for libyang

int LLVMFuzzerTestOneInput_37(const uint8_t *data, size_t size) {
    struct ly_ctx *ctx = NULL;
    struct lyd_node *node = NULL;
    struct lyd_meta *meta = NULL;
    struct lyd_meta *new_meta = NULL;
    LY_ERR err;

    // Initialize the libyang context
    err = ly_ctx_new(NULL, 0, &ctx);
    if (err != LY_SUCCESS) {
        fprintf(stderr, "Failed to create context\n");
        return 0;
    }

    // Create a dummy schema to parse data
    const char *schema = "module test {namespace urn:test;prefix t;leaf dummy {type string;}}";
    lys_parse_mem(ctx, schema, LYS_IN_YANG, NULL);

    // Parse the data into a data tree node
    char *data_str = malloc(size + 1);
    if (data_str == NULL) {
        ly_ctx_destroy(ctx);
        return 0;
    }
    memcpy(data_str, data, size);
    data_str[size] = 0;

    lyd_parse_data_mem(ctx, data_str, LYD_JSON, 0, LYD_VALIDATE_PRESENT, &node);

    // Create a dummy metadata for testing
    if (node) {
        meta = lyd_new_meta(ctx, node, NULL, "test:dummy", "value", 0, NULL);
    }

    // Call the function-under-test
    lyd_dup_meta_single(meta, node, &new_meta);

    // Clean up
    // Removed lyd_free_meta as it does not exist
    lyd_free_all(node);
    ly_ctx_destroy(ctx);
    free(data_str);

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

    LLVMFuzzerTestOneInput_37(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
