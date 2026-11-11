#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "libyang.h"

int LLVMFuzzerTestOneInput_159(const uint8_t *data, size_t size) {
    struct ly_ctx *ctx = NULL;
    struct lyd_node *node1 = NULL;
    struct lyd_node *node2 = NULL;
    LY_ERR err;
    uint32_t options = 0;

    // Initialize libyang context
    err = ly_ctx_new(NULL, 0, &ctx);
    if (err != LY_SUCCESS) {
        fprintf(stderr, "Failed to create context\n");
        return 0;
    }

    // Parse the input data into two separate data trees
    if (size > 0) {
        char *data1 = (char *)malloc(size + 1);
        char *data2 = (char *)malloc(size + 1);
        if (!data1 || !data2) {
            free(data1);
            free(data2);
            ly_ctx_destroy(ctx);
            return 0;
        }

        memcpy(data1, data, size);
        data1[size] = '\0';
        memcpy(data2, data, size);
        data2[size] = '\0';

        // Create two data trees from the same input data
        lyd_parse_data_mem(ctx, data1, LYD_JSON, 0, LYD_VALIDATE_PRESENT, &node1);
        lyd_parse_data_mem(ctx, data2, LYD_JSON, 0, LYD_VALIDATE_PRESENT, &node2);

        // Free the allocated memory for data
        free(data1);
        free(data2);
    }

    // Call the function-under-test
    lyd_compare_single(node1, node2, options);

    // Free the data trees
    lyd_free_all(node1);
    lyd_free_all(node2);

    // Destroy the libyang context
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

    LLVMFuzzerTestOneInput_159(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
