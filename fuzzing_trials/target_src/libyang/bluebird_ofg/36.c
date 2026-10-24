#include <sys/stat.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "libyang.h"

int LLVMFuzzerTestOneInput_36(const uint8_t *data, size_t size) {
    struct ly_ctx *ctx = NULL;
    struct lyd_node *target_tree = NULL;
    struct lyd_node *source_tree = NULL;
    LY_ERR err;
    uint16_t options = 0;

    // Initialize the libyang context
    err = ly_ctx_new(NULL, 0, &ctx);
    if (err != LY_SUCCESS) {
        return 0;
    }

    // Create a dummy schema to parse data
    const char *schema = "module dummy {namespace urn:dummy;prefix d;leaf dummy_leaf {type string;}}";
    lys_parse_mem(ctx, schema, LYS_IN_YANG, NULL);

    // Parse the input data into a source tree
    char *data_copy = malloc(size + 1);
    if (data_copy == NULL) {
        ly_ctx_destroy(ctx);
        return 0;
    }
    memcpy(data_copy, data, size);
    data_copy[size] = '\0';

    lyd_parse_data_mem(ctx, data_copy, LYD_JSON, 0, LYD_VALIDATE_PRESENT, &source_tree);

    // Call the function-under-test
    lyd_merge_tree(&target_tree, source_tree, options);

    // Free resources
    lyd_free_all(target_tree);
    lyd_free_all(source_tree);
    ly_ctx_destroy(ctx);
    free(data_copy);

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
