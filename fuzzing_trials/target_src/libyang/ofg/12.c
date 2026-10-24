#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "libyang.h"

int LLVMFuzzerTestOneInput_12(const uint8_t *data, size_t size) {
    if (size < 2) {
        // Not enough data to split into name and revision
        return 0;
    }

    struct ly_ctx *ctx = NULL;
    const struct lysp_submodule *submodule = NULL;
    char *name = NULL;
    char *revision = NULL;
    LY_ERR err;

    // Initialize libyang context
    err = ly_ctx_new(NULL, 0, &ctx);
    if (err != LY_SUCCESS) {
        fprintf(stderr, "Failed to create context\n");
        return 0;
    }

    // Allocate memory for name and revision, ensuring they are not NULL
    size_t name_size = size / 2;
    size_t revision_size = size - name_size;
    name = malloc(name_size + 1);
    revision = malloc(revision_size + 1);
    if (name == NULL || revision == NULL) {
        ly_ctx_destroy(ctx);
        free(name);
        free(revision);
        return 0;
    }

    // Copy data into name and revision, ensuring they are null-terminated
    memcpy(name, data, name_size);
    name[name_size] = '\0';
    memcpy(revision, data + name_size, revision_size);
    revision[revision_size] = '\0';

    // Call the function-under-test
    submodule = ly_ctx_get_submodule(ctx, name, revision);

    // Clean up
    ly_ctx_destroy(ctx);
    free(name);
    free(revision);

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

    LLVMFuzzerTestOneInput_12(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
