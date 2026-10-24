#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include "libyang.h"

int LLVMFuzzerTestOneInput_151(const uint8_t *data, size_t size) {
    struct ly_ctx *ctx = NULL;
    LY_ERR err;

    // Initialize the context
    err = ly_ctx_new(NULL, 0, &ctx);
    if (err != LY_SUCCESS || ctx == NULL) {
        fprintf(stderr, "Failed to create context\n");
        return 0;
    }

    // Call the function-under-test
    uint16_t change_count = ly_ctx_get_change_count(ctx);

    // Print the change count for debugging purposes
    printf("Change count: %u\n", change_count);

    // Clean up
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

    LLVMFuzzerTestOneInput_151(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
