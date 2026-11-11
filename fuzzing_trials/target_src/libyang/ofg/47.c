#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libyang.h>  // Corrected the include path

int LLVMFuzzerTestOneInput_47(const uint8_t *data, size_t size) {
    struct ly_ctx *ctx = NULL;
    struct lyd_node *tree = NULL;
    const struct lysc_node *schema_node = NULL;
    LY_ERR err;

    // Initialize libyang context
    err = ly_ctx_new(NULL, 0, &ctx);
    if (err != LY_SUCCESS) {
        fprintf(stderr, "Failed to create context\n");
        return 0;
    }

    // Ensure data is null-terminated for parsing
    char *data_copy = (char *)malloc(size + 1);
    if (!data_copy) {
        ly_ctx_destroy(ctx);
        return 0;
    }
    memcpy(data_copy, data, size);
    data_copy[size] = '\0';

    // Parse the input data into a data tree
    lyd_parse_data_mem(ctx, data_copy, LYD_JSON, 0, LYD_VALIDATE_PRESENT, &tree);

    // Call the function-under-test
    if (tree) {
        schema_node = lyd_node_schema(tree);
    }

    // Cleanup
    lyd_free_all(tree);
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

    LLVMFuzzerTestOneInput_47(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
