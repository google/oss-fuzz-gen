#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "/src/libyang/src/parser_schema.h"
#include "/src/libyang/build/libyang/context.h"

int LLVMFuzzerTestOneInput_114(const uint8_t *data, size_t size) {
    struct ly_ctx *ctx = NULL;
    struct lys_module *module = NULL;
    LY_ERR err;
    char *path = NULL;
    LYS_INFORMAT format = LYS_IN_YANG; // Default format

    // Initialize libyang context
    err = ly_ctx_new(NULL, 0, &ctx);
    if (err != LY_SUCCESS) {
        fprintf(stderr, "Failed to create context\n");
        return 0;
    }

    // Allocate memory for path and copy data into it
    path = (char *)malloc(size + 1);
    if (path == NULL) {
        ly_ctx_destroy(ctx);
        return 0;
    }
    memcpy(path, data, size);
    path[size] = '\0'; // Null-terminate the path

    // Parse the path
    lys_parse_path(ctx, path, format, &module);

    // Clean up
    free(path);
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

    LLVMFuzzerTestOneInput_114(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
