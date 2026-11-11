#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libyang.h>  // Corrected the include path

int LLVMFuzzerTestOneInput_92(const uint8_t *data, size_t size) {
    struct ly_ctx *ctx = NULL;
    struct lyd_node *node = NULL;
    struct lyd_node *result = NULL;
    const char *name = "test-name";
    LY_ERR err;

    // Initialize the libyang context
    if (ly_ctx_new(NULL, 0, &ctx) != LY_SUCCESS) {
        fprintf(stderr, "Failed to create libyang context\n");
        return 0;
    }

    // Ensure the data is null-terminated for parsing
    char *data_copy = (char *)malloc(size + 1);
    if (!data_copy) {
        ly_ctx_destroy(ctx);
        return 0;
    }
    memcpy(data_copy, data, size);
    data_copy[size] = '\0';

    // Parse the input data into a libyang data tree
    err = lyd_parse_data_mem(ctx, data_copy, LYD_JSON, 0, LYD_VALIDATE_PRESENT, &node);
    if (err != LY_SUCCESS) {
        free(data_copy);
        ly_ctx_destroy(ctx);
        return 0;
    }

    // Call the function-under-test
    lyd_find_sibling_opaq_next(node, name, &result);

    // Clean up
    lyd_free_all(node);
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

    LLVMFuzzerTestOneInput_92(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
