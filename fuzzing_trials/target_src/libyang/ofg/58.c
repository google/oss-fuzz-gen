#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include "libyang.h"

int LLVMFuzzerTestOneInput_58(const uint8_t *data, size_t size) {
    struct ly_ctx *ctx = NULL;
    struct lyd_node *parent = NULL;
    struct lyd_node *result_tree = NULL;
    struct ly_in *input = NULL;
    LY_ERR err;
    LYD_FORMAT format = LYD_JSON; // Assuming JSON format for fuzzing
    uint32_t parse_options = 0;   // No specific options
    uint32_t validate_options = LYD_VALIDATE_PRESENT; // Basic validation

    // Initialize libyang context
    err = ly_ctx_new(NULL, 0, &ctx);
    if (err != LY_SUCCESS) {
        fprintf(stderr, "Failed to create context\n");
        return 0;
    }

    // Create an input handler from the fuzzing data
    ly_in_new_memory((const char *)data, &input);

    // Call the function-under-test
    err = lyd_parse_data(ctx, parent, input, format, parse_options, validate_options, &result_tree);

    // Clean up
    lyd_free_all(result_tree);
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

    LLVMFuzzerTestOneInput_58(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
