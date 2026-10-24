#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "/src/libyang/src/context.h"
#include "/src/libyang/src/tree_data.h"
#include "/src/libyang/src/validation.h"

int LLVMFuzzerTestOneInput_54(const uint8_t *data, size_t size) {
    struct ly_ctx *ctx = NULL;
    struct lyd_node *tree = NULL;
    struct lyd_node *result_tree = NULL;
    LY_ERR err;
    char *data_copy = NULL;

    // Initialize libyang context
    err = ly_ctx_new(NULL, 0, &ctx);
    if (err != LY_SUCCESS || ctx == NULL) {
        fprintf(stderr, "Failed to create libyang context\n");
        return 0;
    }

    // Allocate and copy input data to a null-terminated string
    data_copy = (char *)malloc(size + 1);
    if (!data_copy) {
        ly_ctx_destroy(ctx);
        return 0;
    }
    memcpy(data_copy, data, size);
    data_copy[size] = '\0';

    // Parse the input data into a data tree
    err = lyd_parse_data_mem(ctx, data_copy, LYD_JSON, LYD_PARSE_ONLY, 0, &tree);
    if (err != LY_SUCCESS) {
        free(data_copy);
        ly_ctx_destroy(ctx);
        return 0;
    }

    // Validate the data tree
    err = lyd_validate_all(&tree, ctx, 0, &result_tree);

    // Free resources
    lyd_free_all(tree);
    lyd_free_all(result_tree);
    free(data_copy);
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

    LLVMFuzzerTestOneInput_54(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
