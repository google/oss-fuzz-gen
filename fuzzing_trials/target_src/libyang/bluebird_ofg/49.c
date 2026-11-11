#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "libyang.h" // Corrected header file

int LLVMFuzzerTestOneInput_49(const uint8_t *data, size_t size) {
    struct ly_ctx *ctx = NULL;
    const struct lys_module *module = NULL; // Changed to const as per libyang v2
    LY_ERR err;
    char *schema = NULL;
    LYS_INFORMAT format = LYS_IN_YANG; // Assuming YANG format for this example

    // Initialize libyang context
    err = ly_ctx_new(NULL, 0, &ctx);
    if (err != LY_SUCCESS) {
        fprintf(stderr, "Failed to create libyang context\n");
        return 0;
    }

    // Allocate memory for schema and copy data
    schema = malloc(size + 1);
    if (!schema) {
        ly_ctx_destroy(ctx);
        return 0;
    }
    memcpy(schema, data, size);
    schema[size] = '\0'; // Null-terminate the schema string

    // Call the function-under-test
    lys_parse_mem(ctx, schema, format, &module);

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

    LLVMFuzzerTestOneInput_49(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
