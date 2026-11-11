#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>  // Include for uint8_t type
#include <libyang.h>  // Correct header file for libyang

int LLVMFuzzerTestOneInput_82(const uint8_t *data, size_t size) {
    struct ly_ctx *ctx = NULL;
    const struct lys_module *module = NULL;
    const struct lysp_submodule *submodule = NULL;
    char *module_name = NULL;
    char *submodule_name = NULL;
    LY_ERR err;

    // Initialize the context
    err = ly_ctx_new(NULL, 0, &ctx);
    if (err != LY_SUCCESS) {
        fprintf(stderr, "Failed to create context\n");
        return 0;
    }

    // Ensure the data is large enough to split into two parts
    if (size < 2) {
        ly_ctx_destroy(ctx);
        return 0;
    }

    // Split the data into two parts: module_name and submodule_name
    size_t module_name_len = size / 2;
    size_t submodule_name_len = size - module_name_len;

    module_name = (char *)malloc(module_name_len + 1);
    submodule_name = (char *)malloc(submodule_name_len + 1);

    if (!module_name || !submodule_name) {
        free(module_name);
        free(submodule_name);
        ly_ctx_destroy(ctx);
        return 0;
    }

    memcpy(module_name, data, module_name_len);
    module_name[module_name_len] = '\0';

    memcpy(submodule_name, data + module_name_len, submodule_name_len);
    submodule_name[submodule_name_len] = '\0';

    // Load a module to the context for testing
    err = lys_parse_mem(ctx, "module test {namespace urn:test;prefix t;}", LYS_IN_YANG, &module);
    if (err != LY_SUCCESS || !module) {
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

    LLVMFuzzerTestOneInput_82(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
