#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libyang.h>  // Corrected include path

int LLVMFuzzerTestOneInput_81(const uint8_t *data, size_t size) {
    struct ly_ctx *ctx = NULL;
    const struct lys_module *module = NULL;
    const struct lysp_submodule *submodule = NULL;
    char *module_name = NULL;
    char *submodule_name = NULL;

    // Initialize libyang context
    if (ly_ctx_new(NULL, 0, &ctx) != LY_SUCCESS) {
        fprintf(stderr, "Failed to create libyang context\n");
        return 0;
    }

    // Ensure the data is large enough to split into module name and submodule name
    if (size < 4) {
        ly_ctx_destroy(ctx);
        return 0;
    }

    // Allocate memory for module and submodule names
    module_name = (char *)malloc(size / 2 + 1);
    submodule_name = (char *)malloc(size / 2 + 1);

    if (!module_name || !submodule_name) {
        free(module_name);
        free(submodule_name);
        ly_ctx_destroy(ctx);
        return 0;
    }

    // Copy data into module and submodule names
    memcpy(module_name, data, size / 2);
    module_name[size / 2] = '\0';
    memcpy(submodule_name, data + size / 2, size / 2);
    submodule_name[size / 2] = '\0';

    // Load a module to the context for testing purposes
    if (lys_parse_mem(ctx, "module test {namespace urn:test;prefix t;}", LYS_IN_YANG, (struct lys_module **)&module) != LY_SUCCESS) {
        free(module_name);
        free(submodule_name);
        ly_ctx_destroy(ctx);
        return 0;
    }

    // Call the function-under-test
    submodule = ly_ctx_get_submodule2_latest(module, submodule_name);

    // Clean up
    free(module_name);
    free(submodule_name);
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

    LLVMFuzzerTestOneInput_81(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
