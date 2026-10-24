#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libyang.h>

int LLVMFuzzerTestOneInput_137(const uint8_t *data, size_t size) {
    struct ly_ctx *ctx = NULL;
    struct lys_module *module = NULL;
    LY_ERR err;

    // Initialize the libyang context
    err = ly_ctx_new(NULL, 0, &ctx);
    if (err != LY_SUCCESS) {
        fprintf(stderr, "Failed to create context\n");
        return 0;
    }

    // Allocate memory for the input data and ensure it's null-terminated
    char *schema_data = (char *)malloc(size + 1);
    if (!schema_data) {
        ly_ctx_destroy(ctx);
        return 0;
    }
    memcpy(schema_data, data, size);
    schema_data[size] = '\0';

    // Fuzz the lys_parse_mem function
    lys_parse_mem(ctx, schema_data, LYS_IN_YANG, &module);

    // Clean up
    free(schema_data);
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

    LLVMFuzzerTestOneInput_137(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
