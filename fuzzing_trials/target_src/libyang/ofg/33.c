#include <stdio.h>
#include <stdlib.h>
#include <string.h>  // Include this for memcpy
#include <libyang.h> // Correct include for libyang

int LLVMFuzzerTestOneInput_33(const uint8_t *data, size_t size) {
    struct ly_ctx *ctx = NULL;
    struct lyd_node *original_tree = NULL;
    struct lyd_node *dup_tree = NULL;
    LY_ERR err;

    // Initialize the context
    if (ly_ctx_new(NULL, 0, &ctx) != LY_SUCCESS) {
        return 0;
    }

    // Load a schema to the context
    const char *schema = "module example {namespace urn:example;prefix ex; container top {leaf foo {type string;}}}";
    if (lys_parse_mem(ctx, schema, LYS_IN_YANG, NULL) != LY_SUCCESS) {
        ly_ctx_destroy(ctx);
        return 0;
    }

    // Parse the input data into a data tree
    char *data_str = malloc(size + 1);
    if (!data_str) {
        ly_ctx_destroy(ctx);
        return 0;
    }
    memcpy(data_str, data, size);
    data_str[size] = '\0';

    lyd_parse_data_mem(ctx, data_str, LYD_JSON, LYD_PARSE_ONLY, 0, &original_tree);
    free(data_str);

    // Duplicate the data tree
    err = lyd_dup_siblings(original_tree, NULL, 0, &dup_tree);

    // Free the data trees and context
    lyd_free_all(original_tree);
    lyd_free_all(dup_tree);
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

    LLVMFuzzerTestOneInput_33(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
