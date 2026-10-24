#include <stdio.h>
#include <stdlib.h>
#include <stdint.h> // Include for uint8_t and uint32_t
#include <libyang.h> // Corrected path for libyang header

int LLVMFuzzerTestOneInput_74(const uint8_t *data, size_t size) {
    struct ly_ctx *ctx = NULL;
    LY_ERR err;

    // Initialize the libyang context
    err = ly_ctx_new(NULL, 0, &ctx);
    if (err != LY_SUCCESS) {
        fprintf(stderr, "Failed to create context\n");
        return 0;
    }

    // Ensure the input data is not null and has a valid size
    if (data != NULL && size > 0) {
        // Call the function-under-test
        uint32_t module_count = ly_ctx_internal_modules_count(ctx);

        // Print the count (for debugging purposes)
        printf("Internal modules count: %u\n", module_count);
    }

    // Clean up the context
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

    LLVMFuzzerTestOneInput_74(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
