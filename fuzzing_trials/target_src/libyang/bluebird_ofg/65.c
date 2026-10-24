#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "libyang.h"

int LLVMFuzzerTestOneInput_65(const uint8_t *data, size_t size) {
    struct ly_ctx *ctx = NULL;
    struct lyd_node *parent = NULL;
    struct lyd_node *new_node = NULL;
    LY_ERR err;

    // Initialize the libyang context
    err = ly_ctx_new(NULL, 0, &ctx);
    if (err != LY_SUCCESS) {
        fprintf(stderr, "Failed to create context\n");
        return 0;
    }

    // Ensure data is null-terminated
    char *name = malloc(size + 1);
    if (!name) {
        ly_ctx_destroy(ctx);
        return 0;
    }
    memcpy(name, data, size);
    name[size] = '\0';

    // Use fixed non-NULL strings for the other parameters
    const char *value = "value";
    const char *module_key = "module-key";
    const char *module_name = "module-name";

    // Call the function-under-test
    err = lyd_new_opaq(parent, ctx, name, value, module_key, module_name, &new_node);

    // Clean up
    lyd_free_all(new_node);
    ly_ctx_destroy(ctx);
    free(name);

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

    LLVMFuzzerTestOneInput_65(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
