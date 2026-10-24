#include <sys/stat.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "libyang.h"  // Include the correct libyang header

int LLVMFuzzerTestOneInput_50(const uint8_t *data, size_t size) {
    struct ly_ctx *ctx = NULL;
    const struct lys_module *module = NULL;  // Use 'const' for the module pointer
    uint32_t index = 0;
    LY_ERR err;

    // Initialize the libyang context
    err = ly_ctx_new(NULL, 0, &ctx);
    if (err != LY_SUCCESS) {
        fprintf(stderr, "Failed to create context\n");
        return 0;
    }

    // Use the input data to create a YANG module in the context
    char *yang_data = (char *)malloc(size + 1);
    if (!yang_data) {
        ly_ctx_destroy(ctx);
        return 0;
    }
    memcpy(yang_data, data, size);
    yang_data[size] = '\0';  // Ensure null-termination

    // Attempt to parse the input data as a YANG module
    err = lys_parse_mem(ctx, yang_data, LYS_IN_YANG, &module);
    if (err != LY_SUCCESS) {
        fprintf(stderr, "Failed to parse YANG module\n");
    } else {
        // Iterate over modules if parsing was successful
        module = ly_ctx_get_module_iter(ctx, &index);
    }

    // Clean up
    free(yang_data);
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
