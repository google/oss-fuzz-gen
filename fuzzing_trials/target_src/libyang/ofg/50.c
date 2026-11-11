#include <stdio.h>
#include <stdlib.h>
#include <string.h> // Include string.h for memcpy
#include <libyang.h> // Correct include path for libyang

int LLVMFuzzerTestOneInput_50(const uint8_t *data, size_t size) {
    struct ly_ctx *ctx = NULL;
    LY_ERR err;

    // Initialize the libyang context
    err = ly_ctx_new(NULL, 0, &ctx);
    if (err != LY_SUCCESS) {
        fprintf(stderr, "Failed to create context\n");
        return 0;
    }

    // Create a temporary buffer to store the input data
    char *schema = malloc(size + 1);
    if (!schema) {
        ly_ctx_destroy(ctx);
        return 0;
    }

    // Copy the input data to the schema buffer and null-terminate it
    memcpy(schema, data, size);
    schema[size] = '\0';

    // Parse the schema to add it to the context
    lys_parse_mem(ctx, schema, LYS_IN_YANG, NULL);

    // Call the function-under-test
    ly_ctx_compile(ctx);

    // Clean up
    free(schema);
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

    LLVMFuzzerTestOneInput_50(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
