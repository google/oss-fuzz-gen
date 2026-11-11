#include <sys/stat.h>
#include "stdbool.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "libyang.h"

int LLVMFuzzerTestOneInput_34(const uint8_t *data, size_t size) {
    struct ly_ctx *ctx = NULL;
    const char *pattern = "[a-z]*";
    char *value = NULL;
    uint32_t options = 0;
    void *context = NULL;
    LY_ERR err;

    // Initialize libyang context
    err = ly_ctx_new(NULL, 0, &ctx);
    if (err != LY_SUCCESS) {
        fprintf(stderr, "Failed to create context\n");
        exit(EXIT_FAILURE);
    }

    // Allocate memory for value and copy data
    value = malloc(size + 1);
    if (value == NULL) {
        ly_ctx_destroy(ctx);
        return 0;
    }
    memcpy(value, data, size);
    value[size] = '\0';

    // Call the function-under-test
    err = ly_pattern_match(ctx, pattern, value, options, &context);

    // Clean up
    free(value);
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

    LLVMFuzzerTestOneInput_34(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
