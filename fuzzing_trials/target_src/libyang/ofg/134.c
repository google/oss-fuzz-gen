#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <libyang.h>  // Corrected header file for libyang

int LLVMFuzzerTestOneInput_134(const uint8_t *data, size_t size) {
    struct ly_ctx *ctx = NULL;
    struct lyd_node *node1 = NULL, *node2 = NULL;
    const char *schema = "module test {namespace urn:test;prefix t; container cont {leaf leaf1 {type string;} leaf leaf2 {type string;}}}";
    LY_ERR err;

    // Initialize libyang context
    err = ly_ctx_new(NULL, 0, &ctx);
    if (err != LY_SUCCESS) {
        fprintf(stderr, "Failed to create context\n");
        return 0;
    }

    // Parse the schema
    if (lys_parse_mem(ctx, schema, LYS_IN_YANG, NULL) != LY_SUCCESS) {
        fprintf(stderr, "Failed to parse schema\n");
        ly_ctx_destroy(ctx);
        return 0;
    }

    // Create a buffer for data manipulation
    char *data_buffer = malloc(size + 1);
    if (!data_buffer) {
        ly_ctx_destroy(ctx);
        return 0;
    }

    // Copy and null-terminate the input data
    memcpy(data_buffer, data, size);
    data_buffer[size] = '\0';

    // Parse the input data into two separate data trees
    lyd_parse_data_mem(ctx, data_buffer, LYD_JSON, 0, LYD_VALIDATE_PRESENT, &node1);
    lyd_parse_data_mem(ctx, data_buffer, LYD_JSON, 0, LYD_VALIDATE_PRESENT, &node2);

    // Call the function under test
    lyd_compare_siblings(node1, node2, 0);

    // Clean up
    lyd_free_all(node1);
    lyd_free_all(node2);
    ly_ctx_destroy(ctx);
    free(data_buffer);

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

    LLVMFuzzerTestOneInput_134(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
