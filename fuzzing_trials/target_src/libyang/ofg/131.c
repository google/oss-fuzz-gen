#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "libyang.h"

int LLVMFuzzerTestOneInput_131(const uint8_t *data, size_t size) {
    struct ly_ctx *ctx = NULL;
    LY_ERR err;
    char *searchdir = NULL;

    // Initialize the libyang context
    err = ly_ctx_new(NULL, 0, &ctx);
    if (err != LY_SUCCESS) {
        fprintf(stderr, "Failed to create context\n");
        return 0;
    }

    // Allocate memory for the search directory string and ensure it's null-terminated
    searchdir = (char *)malloc(size + 1);
    if (searchdir == NULL) {
        ly_ctx_destroy(ctx);
        return 0;
    }
    memcpy(searchdir, data, size);
    searchdir[size] = '\0';

    // Call the function-under-test
    ly_ctx_set_searchdir(ctx, searchdir);

    // Clean up
    free(searchdir);
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

    LLVMFuzzerTestOneInput_131(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
