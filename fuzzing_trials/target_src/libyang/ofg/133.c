#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "libyang.h"

int LLVMFuzzerTestOneInput_133(const uint8_t *data, size_t size) {
    struct ly_ctx *ctx = NULL;
    struct lyd_node *node1 = NULL, *node2 = NULL;
    LY_ERR err;
    uint32_t options = 0; // Default options, can be modified for more variations

    // Initialize libyang context
    err = ly_ctx_new(NULL, 0, &ctx);
    if (err != LY_SUCCESS) {
        return 0;
    }

    // Create a dummy schema for testing
    const char *schema = "module test {namespace urn:test;prefix t;container cont {leaf l1 {type string;} leaf l2 {type int8;}}}";
    lys_parse_mem(ctx, schema, LYS_IN_YANG, NULL);

    // Allocate and initialize data for two sibling nodes
    char *data1 = malloc(size + 1);
    char *data2 = malloc(size + 1);
    if (data1 == NULL || data2 == NULL) {
        ly_ctx_destroy(ctx);
        free(data1);
        free(data2);
        return 0;
    }
    
    memcpy(data1, data, size);
    data1[size] = '\0';
    memcpy(data2, data, size);
    data2[size] = '\0';

    // Parse the data into two sibling nodes
    lyd_parse_data_mem(ctx, data1, LYD_JSON, 0, LYD_VALIDATE_PRESENT, &node1);
    lyd_parse_data_mem(ctx, data2, LYD_JSON, 0, LYD_VALIDATE_PRESENT, &node2);

    // Call the function-under-test
    lyd_compare_siblings(node1, node2, options);

    // Clean up
    lyd_free_all(node1);
    lyd_free_all(node2);
    ly_ctx_destroy(ctx);
    free(data1);
    free(data2);

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

    LLVMFuzzerTestOneInput_133(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
