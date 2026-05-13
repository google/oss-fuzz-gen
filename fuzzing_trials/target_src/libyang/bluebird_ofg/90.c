#include <sys/stat.h>
#include "stdbool.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "libyang.h"  // Corrected include path

int LLVMFuzzerTestOneInput_90(const uint8_t *data, size_t size) {
    if (data == NULL || size == 0) {
        return 0;  // No data to process
    }

    struct ly_ctx *ctx = NULL;
    LY_ERR err;
    const struct lys_module *module = NULL;

    // Initialize the libyang context
    err = ly_ctx_new(NULL, 0, &ctx);
    if (err != LY_SUCCESS) {
        fprintf(stderr, "Failed to create context\n");
        return 0;
    }

    // Attempt to parse the input data as a YANG module
    char *yang_data = (char *)malloc(size + 1);
    if (!yang_data) {
        fprintf(stderr, "Memory allocation failed\n");
        ly_ctx_destroy(ctx);
        return 0;
    }
    memcpy(yang_data, data, size);
    yang_data[size] = '\0';  // Ensure null-termination

    err = lys_parse_mem(ctx, yang_data, LYS_IN_YANG, &module);
    free(yang_data);

    if (err != LY_SUCCESS) {
        // Parsing failed, but this is expected for invalid inputs
        ly_ctx_destroy(ctx);
        return 0;
    }

    // Clean up
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

    LLVMFuzzerTestOneInput_90(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
