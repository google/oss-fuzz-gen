#include <sys/stat.h>
#include <stdint.h>
#include <stdlib.h>
#include "stdbool.h"
#include <stdio.h>
#include <string.h>
#include "libyang.h"

int LLVMFuzzerTestOneInput_35(const uint8_t *data, size_t size) {
    struct ly_ctx *ctx = NULL;
    struct lyd_node *root = NULL, *child = NULL;
    const char *schema = "module test {namespace urn:test;prefix t;container cont {leaf leaf1 {type string;}}}";
    LY_ERR err;

    // Initialize the libyang context
    err = ly_ctx_new(NULL, 0, &ctx);
    if (err != LY_SUCCESS) {
        fprintf(stderr, "Failed to create context\n");
        return 0;
    }

    // Parse the schema
    err = lys_parse_mem(ctx, schema, LYS_IN_YANG, NULL);
    if (err != LY_SUCCESS) {
        fprintf(stderr, "Failed to parse schema\n");
        ly_ctx_destroy(ctx);
        return 0;
    }

    // Allocate memory for the data buffer
    char *data_buf = malloc(size + 1);
    if (!data_buf) {
        ly_ctx_destroy(ctx);
        return 0;
    }

    // Copy the input data to the buffer and null-terminate it
    memcpy(data_buf, data, size);
    data_buf[size] = '\0';

    // Parse the data buffer to create a data tree
    err = lyd_parse_data_mem(ctx, data_buf, LYD_JSON, 0, LYD_VALIDATE_PRESENT, &root);
    if (err != LY_SUCCESS) {
        fprintf(stderr, "Failed to parse data\n");
        free(data_buf);
        ly_ctx_destroy(ctx);
        return 0;
    }

    // Call the function-under-test
    child = lyd_child_no_keys(root);

    // Clean up
    lyd_free_all(root);
    free(data_buf);
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

    LLVMFuzzerTestOneInput_35(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
