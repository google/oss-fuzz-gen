#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "libyang.h" // Corrected path to the libyang header

int LLVMFuzzerTestOneInput_58(const uint8_t *data, size_t size) {
    struct ly_ctx *ctx = NULL;
    const struct lys_module *module = NULL;
    LY_ERR err;

    // Check if input data is non-null and has a positive size
    if (data == NULL || size == 0) {
        return 0;
    }

    // Initialize the libyang context
    err = ly_ctx_new(NULL, 0, &ctx);
    if (err != LY_SUCCESS || ctx == NULL) {
        fprintf(stderr, "Failed to create libyang context\n");
        return 0;
    }

    // Ensure the input is null-terminated for proper string handling
    char *yang_data = (char *)malloc(size + 1);
    if (!yang_data) {
        ly_ctx_destroy(ctx);
        return 0;
    }
    memcpy(yang_data, data, size);
    yang_data[size] = '\0';

    // Parse the input data as a YANG module
    err = lys_parse_mem(ctx, yang_data, LYS_IN_YANG, &module);
    if (err != LY_SUCCESS) {
        // Parsing failed, but this is expected for random input
        free(yang_data);
        ly_ctx_destroy(ctx);
        return 0;
    }

    // Clean up
    free(yang_data);
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

    LLVMFuzzerTestOneInput_58(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
