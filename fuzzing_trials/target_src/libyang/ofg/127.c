#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "libyang.h"

int LLVMFuzzerTestOneInput_127(const uint8_t *data, size_t size) {
    struct ly_ctx *ctx = NULL;
    struct ly_in *input = NULL;
    struct lyd_node *node = NULL;
    LY_ERR err;
    const char *name = "test";

    // Initialize libyang context
    err = ly_ctx_new(NULL, 0, &ctx);
    if (err != LY_SUCCESS) {
        fprintf(stderr, "Failed to create context\n");
        return 0;
    }

    // Create a new input handler
    err = ly_in_new_memory((const char *)data, &input);
    if (err != LY_SUCCESS) {
        fprintf(stderr, "Failed to create input handler\n");
        ly_ctx_destroy(ctx);
        return 0;
    }

    // Call the function-under-test
    err = lyd_parse_value_fragment(ctx, name, input, LYD_JSON, 0, 0, 0, &node);

    // Clean up
    lyd_free_all(node);
    ly_in_free(input, 0);
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

    LLVMFuzzerTestOneInput_127(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
