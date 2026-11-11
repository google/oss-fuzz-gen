#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "libyang.h"

int LLVMFuzzerTestOneInput_4(const uint8_t *data, size_t size) {
    struct ly_ctx *ctx = NULL;
    struct lyd_node *tree = NULL;
    LY_ERR err;
    LYD_FORMAT format = LYD_JSON; // Assuming JSON format for fuzzing
    uint32_t parse_options = 0;
    uint32_t validate_options = LYD_VALIDATE_PRESENT;

    // Initialize libyang context
    err = ly_ctx_new(NULL, 0, &ctx);
    if (err != LY_SUCCESS) {
        fprintf(stderr, "Failed to create context\n");
        return 0;
    }

    // Allocate memory for the input data
    char *input_data = (char *)malloc(size + 1);
    if (!input_data) {
        ly_ctx_destroy(ctx);
        return 0;
    }

    // Copy the fuzzing data into the input buffer and null-terminate it
    memcpy(input_data, data, size);
    input_data[size] = '\0';

    // Call the function-under-test
    lyd_parse_data_mem(ctx, input_data, format, parse_options, validate_options, &tree);

    // Clean up
    lyd_free_all(tree);
    ly_ctx_destroy(ctx);
    free(input_data);

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

    LLVMFuzzerTestOneInput_4(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
