#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "libyang.h"

int LLVMFuzzerTestOneInput_51(const uint8_t *data, size_t size) {
    struct ly_ctx *ctx = NULL;
    struct lys_module *module = NULL;
    char *module_data = NULL;
    LY_ERR err;
    static bool log = false;

    if (!log) {
        ly_log_options(0);
        log = true;
    }

    // Create a new context
    err = ly_ctx_new(NULL, 0, &ctx);
    if (err != LY_SUCCESS) {
        fprintf(stderr, "Failed to create context\n");
        exit(EXIT_FAILURE);
    }

    // Ensure the data is null-terminated for string operations
    module_data = malloc(size + 1);
    if (module_data == NULL) {
        ly_ctx_destroy(ctx);
        return 0;
    }
    memcpy(module_data, data, size);
    module_data[size] = '\0';

    // Parse the input data as a YANG module
    err = lys_parse_mem(ctx, module_data, LYS_IN_YANG, &module);
    if (err != LY_SUCCESS) {
        // If parsing fails, clean up and return
        ly_ctx_destroy(ctx);
        free(module_data);
        return 0;
    }

    // Call the function-under-test
    module = ly_ctx_get_module_latest(ctx, module->name);

    // Clean up
    ly_ctx_destroy(ctx);
    free(module_data);

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

    LLVMFuzzerTestOneInput_51(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
