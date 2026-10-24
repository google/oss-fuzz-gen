#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libyang.h>  // Corrected include directive

int LLVMFuzzerTestOneInput_87(const uint8_t *data, size_t size) {
    struct ly_ctx *ctx = NULL;
    struct lys_module *module = NULL;
    char *module_name = NULL;
    char *revision = NULL;
    LY_ERR err;

    // Initialize the context
    err = ly_ctx_new(NULL, 0, &ctx);
    if (err != LY_SUCCESS) {
        fprintf(stderr, "Failed to create context\n");
        return 0;
    }

    // Allocate memory for module_name and revision, ensuring they are null-terminated
    module_name = (char *)malloc(size + 1);
    if (!module_name) {
        ly_ctx_destroy(ctx);
        return 0;
    }
    memcpy(module_name, data, size);
    module_name[size] = '\0';

    // For simplicity, use the same data for revision
    revision = (char *)malloc(size + 1);
    if (!revision) {
        free(module_name);
        ly_ctx_destroy(ctx);
        return 0;
    }
    memcpy(revision, data, size);
    revision[size] = '\0';

    // Call the function-under-test
    module = ly_ctx_get_module(ctx, module_name, revision);

    // Clean up
    free(module_name);
    free(revision);
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

    LLVMFuzzerTestOneInput_87(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
