#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <libyang.h> // Corrected header file

int LLVMFuzzerTestOneInput_23(const uint8_t *data, size_t size) {
    struct ly_ctx *ctx = NULL;
    struct lyd_node *tree = NULL;
    LY_ERR err;

    // Initialize the libyang context
    err = ly_ctx_new(NULL, 0, &ctx);
    if (err != LY_SUCCESS) {
        return 0;
    }

    // Parse the input data as a YANG data tree
    char *data_str = (char *)malloc(size + 1);
    if (data_str == NULL) {
        ly_ctx_destroy(ctx);
        return 0;
    }
    memcpy(data_str, data, size);
    data_str[size] = '\0';

    err = lyd_parse_data_mem(ctx, data_str, LYD_JSON, 0, LYD_VALIDATE_PRESENT, &tree);
    free(data_str);

    if (err == LY_SUCCESS && tree != NULL) {
        // Call the function-under-test
        lyd_parse_opaq_error(tree);

        // Free the data tree
        lyd_free_all(tree);
    }

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

    LLVMFuzzerTestOneInput_23(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
