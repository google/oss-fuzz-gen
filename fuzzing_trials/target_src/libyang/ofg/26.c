#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include "libyang.h"

// Function under test
uint32_t ly_ctx_get_modules_hash(const struct ly_ctx *);

int LLVMFuzzerTestOneInput_26(const uint8_t *data, size_t size) {
    struct ly_ctx *ctx = NULL;
    LY_ERR err;
    static bool log = false;

    // Initialize logging options once
    if (!log) {
        ly_log_options(0);
        log = true;
    }

    // Create a new libyang context
    err = ly_ctx_new(NULL, 0, &ctx);
    if (err != LY_SUCCESS) {
        fprintf(stderr, "Failed to create context\n");
        return 0;
    }

    // Parse the input data as a YANG schema
    char *schema_data = malloc(size + 1);
    if (schema_data == NULL) {
        ly_ctx_destroy(ctx);
        return 0;
    }
    memcpy(schema_data, data, size);
    schema_data[size] = '\0';

    // Attempt to parse the schema data
    lys_parse_mem(ctx, schema_data, LYS_IN_YANG, NULL);

    // Call the function under test
    uint32_t hash = ly_ctx_get_modules_hash(ctx);

    // Clean up
    free(schema_data);
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

    LLVMFuzzerTestOneInput_26(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
