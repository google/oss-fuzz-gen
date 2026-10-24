#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "/src/libyang/src/context.h"
#include "/src/libyang/src/tree_data.h"
#include "/src/libyang/src/validation.h"

int LLVMFuzzerTestOneInput_142(const uint8_t *data, size_t size) {
    struct ly_ctx *ctx = NULL;
    struct lyd_node *node = NULL;
    struct lyd_node *tree = NULL;
    LY_ERR err;

    // Create a new libyang context
    err = ly_ctx_new(NULL, 0, &ctx);
    if (err != LY_SUCCESS) {
        fprintf(stderr, "Failed to create context\n");
        return 0;
    }

    // Parse the input data into a libyang data tree
    if (size > 0) {
        char *input_data = (char *)malloc(size + 1);
        if (!input_data) {
            ly_ctx_destroy(ctx);
            return 0;
        }
        memcpy(input_data, data, size);
        input_data[size] = '\0';

        lyd_parse_data_mem(ctx, input_data, LYD_JSON, 0, LYD_VALIDATE_PRESENT, &node);
        free(input_data);
    }

    // Call the function-under-test
    lyd_validate_op(node, NULL, 0, &tree);

    // Clean up
    lyd_free_all(node);
    lyd_free_all(tree);
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

    LLVMFuzzerTestOneInput_142(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
