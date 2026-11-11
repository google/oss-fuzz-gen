#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <libyang.h>  // Corrected the include path

int LLVMFuzzerTestOneInput_45(const uint8_t *data, size_t size) {
    struct ly_ctx *ctx = NULL;
    struct lyd_node *source_node = NULL;
    struct lyd_node *parent_node = NULL;
    struct lyd_node *duplicated_node = NULL;
    LY_ERR err;
    char *json_data = NULL;

    // Initialize the libyang context
    if (ly_ctx_new(NULL, 0, &ctx) != LY_SUCCESS) {
        fprintf(stderr, "Failed to create libyang context\n");
        return 0;
    }

    // Allocate memory for JSON data and ensure it's null-terminated
    json_data = (char *)malloc(size + 1);
    if (!json_data) {
        ly_ctx_destroy(ctx);
        return 0;
    }
    memcpy(json_data, data, size);
    json_data[size] = '\0';

    // Parse the input data as a JSON tree
    err = lyd_parse_data_mem(ctx, json_data, LYD_JSON, 0, LYD_VALIDATE_PRESENT, &source_node);
    if (err != LY_SUCCESS) {
        free(json_data);
        ly_ctx_destroy(ctx);
        return 0;
    }

    // Call the function-under-test
    lyd_dup_siblings_to_ctx(source_node, ctx, parent_node, 0, &duplicated_node);

    // Free resources
    lyd_free_all(source_node);
    lyd_free_all(duplicated_node);
    ly_ctx_destroy(ctx);
    free(json_data);

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

    LLVMFuzzerTestOneInput_45(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
