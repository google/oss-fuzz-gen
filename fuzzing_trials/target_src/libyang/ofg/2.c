#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "libyang.h"

int LLVMFuzzerTestOneInput_2(const uint8_t *data, size_t size) {
    struct lyd_node *parent = NULL;
    struct lyd_node *new_node = NULL;
    struct ly_ctx *ctx = NULL;
    const char *name = "example-name";
    const char *value = "example-value";
    const char *module_name = "example-module";
    const char *prefix = "ex";
    LY_ERR err;

    // Initialize the libyang context
    err = ly_ctx_new(NULL, 0, &ctx);
    if (err != LY_SUCCESS) {
        fprintf(stderr, "Failed to create context\n");
        return 0;
    }

    // Use the input data as the name if size is large enough
    if (size > 0) {
        // Allocate memory for a null-terminated string
        char *name_buffer = (char *)malloc(size + 1);
        if (!name_buffer) {
            fprintf(stderr, "Failed to allocate memory\n");
            ly_ctx_destroy(ctx);
            return 0;
        }

        // Copy the data and ensure null-termination
        memcpy(name_buffer, data, size);
        name_buffer[size] = '\0';
        name = name_buffer;
    }

    // Call the function-under-test
    err = lyd_new_opaq2(parent, ctx, name, value, module_name, prefix, &new_node);

    // Cleanup
    lyd_free_all(new_node);
    ly_ctx_destroy(ctx);
    if (size > 0) {
        free((void *)name); // Free the allocated memory if it was used
    }

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

    LLVMFuzzerTestOneInput_2(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
