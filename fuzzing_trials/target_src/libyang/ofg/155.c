#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libyang.h>  // Corrected include directive

int LLVMFuzzerTestOneInput_155(const uint8_t *data, size_t size) {
    struct ly_ctx *ctx = NULL;
    struct lyd_node *root = NULL;
    LY_ERR err;
    const char *schema = "module test {namespace urn:test;prefix t;leaf myleaf {type string; default \"default\";}}";

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

    // Allocate memory for data and ensure it's null-terminated
    char *data_copy = (char *)malloc(size + 1);
    if (!data_copy) {
        ly_ctx_destroy(ctx);
        return 0;
    }
    memcpy(data_copy, data, size);
    data_copy[size] = '\0';

    // Parse the data into a data tree
    err = lyd_parse_data_mem(ctx, data_copy, LYD_JSON, LYD_PARSE_ONLY, 0, &root);
    if (err == LY_SUCCESS && root) {
        // Call the function-under-test
        ly_bool is_default = lyd_is_default(root);
        (void)is_default; // Suppress unused variable warning
    }

    // Clean up
    lyd_free_all(root);
    free(data_copy);
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

    LLVMFuzzerTestOneInput_155(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
