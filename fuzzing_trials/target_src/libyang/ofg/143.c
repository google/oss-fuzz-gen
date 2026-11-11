#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "/src/libyang/src/context.h"
#include "/src/libyang/src/tree.h"
#include "/src/libyang/src/validation.h"
#include "/src/libyang/src/in.h"

int LLVMFuzzerTestOneInput_143(const uint8_t *data, size_t size) {
    struct ly_ctx *ctx = NULL;
    struct lyd_node *node = NULL;
    struct lyd_node *result = NULL;
    const struct lyd_node *tree = NULL;
    LY_ERR err;

    // Initialize libyang context
    err = ly_ctx_new(NULL, 0, &ctx);
    if (err != LY_SUCCESS) {
        fprintf(stderr, "Failed to create context\n");
        return 0;
    }

    // Parse the input data into a data tree
    char *data_str = (char *)malloc(size + 1);
    if (data_str == NULL) {
        ly_ctx_destroy(ctx);
        return 0;
    }
    memcpy(data_str, data, size);
    data_str[size] = '\0';

    // Parse the data into a libyang data tree
    err = lyd_parse_data_mem(ctx, data_str, LYD_JSON, LYD_PARSE_ONLY, 0, &node);
    if (err != LY_SUCCESS) {
        free(data_str);
        ly_ctx_destroy(ctx);
        return 0;
    }

    // Call the function-under-test
    err = lyd_validate_op(node, tree, LYD_TYPE_DATA_YANG, &result);

    // Clean up
    lyd_free_all(node);
    lyd_free_all(result);
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

    LLVMFuzzerTestOneInput_143(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
