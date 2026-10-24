#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include "libyang.h"

int LLVMFuzzerTestOneInput_63(const uint8_t *data, size_t size) {
    struct ly_ctx *ctx = NULL;
    const struct lysp_submodule *submodule;
    const char *submodule_name;
    bool log = false;
    LY_ERR err;

    if (!log) {
        ly_log_options(0);
        log = true;
    }

    // Create a new libyang context
    err = ly_ctx_new(NULL, 0, &ctx);
    if (err != LY_SUCCESS) {
        fprintf(stderr, "Failed to create context\n");
        exit(EXIT_FAILURE);
    }

    // Prepare submodule name from input data
    submodule_name = (const char *)malloc(size + 1);
    if (submodule_name == NULL) {
        ly_ctx_destroy(ctx);
        return 0;
    }
    memcpy((char *)submodule_name, data, size);
    ((char *)submodule_name)[size] = '\0';

    // Call the function-under-test
    submodule = ly_ctx_get_submodule_latest(ctx, submodule_name);

    // Cleanup
    free((char *)submodule_name);
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

    LLVMFuzzerTestOneInput_63(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
