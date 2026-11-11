#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h> // Include for uint8_t
#include <libyang.h> // Corrected include for libyang

int LLVMFuzzerTestOneInput_57(const uint8_t *data, size_t size) {
    struct ly_ctx *ctx = NULL;
    struct lyd_node *root = NULL;
    struct lyd_node *sibling = NULL;
    LY_ERR err;

    // Initialize the libyang context
    err = ly_ctx_new(NULL, 0, &ctx);
    if (err != LY_SUCCESS) {
        fprintf(stderr, "Failed to create context\n");
        return 0;
    }

    // Create a dummy schema for testing
    const char *schema = "module test {namespace urn:test;prefix t;yang-version 1.1;"
                         "container cont {leaf leaf1 {type string;} leaf leaf2 {type string;}}}";

    // Parse the schema
    err = lys_parse_mem(ctx, schema, LYS_IN_YANG, NULL);
    if (err != LY_SUCCESS) {
        fprintf(stderr, "Failed to parse schema\n");
        ly_ctx_destroy(ctx);
        return 0;
    }

    // Prepare data buffer with a null-terminated string
    char *data_buf = malloc(size + 1);
    if (!data_buf) {
        ly_ctx_destroy(ctx);
        return 0;
    }
    memcpy(data_buf, data, size);
    data_buf[size] = '\0';

    // Parse the data into a data tree
    err = lyd_parse_data_mem(ctx, data_buf, LYD_JSON, LYD_PARSE_ONLY, 0, &root);
    if (err == LY_SUCCESS && root != NULL) {
        // Call the function-under-test
        sibling = lyd_first_sibling(root);

        // Free the sibling node if it's different from root
        if (sibling != root) {
            lyd_free_all(sibling);
        }
        lyd_free_all(root);
    }

    // Clean up
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

    LLVMFuzzerTestOneInput_57(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
