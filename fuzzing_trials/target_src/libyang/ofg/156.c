#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "libyang.h"

int LLVMFuzzerTestOneInput_156(const uint8_t *data, size_t size) {
    struct ly_ctx *ctx = NULL;
    struct lyd_node *root = NULL;
    LY_ERR err;

    // Initialize the libyang context
    err = ly_ctx_new(NULL, 0, &ctx);
    if (err != LY_SUCCESS) {
        fprintf(stderr, "Failed to create context\n");
        return 0;
    }

    // Allocate and copy input data to a string
    char *input_data = malloc(size + 1);
    if (input_data == NULL) {
        ly_ctx_destroy(ctx);
        return 0;
    }
    memcpy(input_data, data, size);
    input_data[size] = '\0';

    // Parse the input data into a lyd_node structure
    err = lyd_parse_data_mem(ctx, input_data, LYD_XML, LYD_PARSE_ONLY, 0, &root);
    if (err != LY_SUCCESS) {
        fprintf(stderr, "Failed to parse lyd_node\n");
        free(input_data);
        ly_ctx_destroy(ctx);
        return 0;
    }

    // Clean up
    lyd_free_all(root);
    free(input_data);
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

    LLVMFuzzerTestOneInput_156(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
