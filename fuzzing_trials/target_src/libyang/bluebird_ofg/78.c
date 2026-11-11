#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "libyang.h"  // Corrected header file

int LLVMFuzzerTestOneInput_78(const uint8_t *data, size_t size) {
    struct ly_ctx *ctx = NULL;
    struct lyd_node *tree = NULL;
    LY_ERR err;
    
    // Initialize the libyang context
    err = ly_ctx_new(NULL, 0, &ctx);
    if (err != LY_SUCCESS) {
        fprintf(stderr, "Failed to create libyang context\n");
        return 0;
    }

    // Allocate memory for the input data and ensure it is null-terminated
    char *input_data = (char *)malloc(size + 1);
    if (input_data == NULL) {
        ly_ctx_destroy(ctx);
        return 0;
    }
    memcpy(input_data, data, size);
    input_data[size] = '\0';

    // Call the function-under-test with the fuzzed input
    lyd_parse_data_mem(ctx, input_data, LYD_JSON, 0, LYD_VALIDATE_PRESENT, &tree);

    // Cleanup
    lyd_free_all(tree);
    ly_ctx_destroy(ctx);
    free(input_data);

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

    LLVMFuzzerTestOneInput_78(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
