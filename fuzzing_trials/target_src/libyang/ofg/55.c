#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <libyang.h> // Corrected header file inclusion

int LLVMFuzzerTestOneInput_55(const uint8_t *data, size_t size) {
    struct ly_ctx *ctx = NULL;
    LY_ERR err;
    uint32_t index;

    // Initialize the context
    err = ly_ctx_new(NULL, 0, &ctx);
    if (err != LY_SUCCESS) {
        fprintf(stderr, "Failed to create context\n");
        return 0;
    }

    // Ensure size is large enough to extract an index
    if (size < sizeof(uint32_t)) {
        ly_ctx_destroy(ctx);
        return 0;
    }

    // Extract an index from the data
    index = *((uint32_t *)data);

    // Call the function-under-test
    ly_ctx_unset_searchdir_last(ctx, index);

    // Cleanup
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

    LLVMFuzzerTestOneInput_55(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
