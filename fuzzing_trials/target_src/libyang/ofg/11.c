#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include "libyang.h"

int LLVMFuzzerTestOneInput_11(const uint8_t *data, size_t size) {
    struct ly_ctx *ctx = NULL;
    const struct lysp_submodule *submodule = NULL;
    char *module_name = NULL;
    char *submodule_name = NULL;
    LY_ERR err;
    static bool log = false;

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

    // Allocate memory for module_name and submodule_name
    module_name = (char *)malloc(size + 1);
    submodule_name = (char *)malloc(size + 1);

    if (module_name == NULL || submodule_name == NULL) {
        ly_ctx_destroy(ctx);
        free(module_name);
        free(submodule_name);
        return 0;
    }

    // Copy data into module_name and submodule_name
    memcpy(module_name, data, size);
    memcpy(submodule_name, data, size);

    // Null-terminate the strings
    module_name[size] = '\0';
    submodule_name[size] = '\0';

    // Call the function-under-test
    submodule = ly_ctx_get_submodule(ctx, module_name, submodule_name);

    // Clean up
    ly_ctx_destroy(ctx);
    free(module_name);
    free(submodule_name);

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

    LLVMFuzzerTestOneInput_11(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
