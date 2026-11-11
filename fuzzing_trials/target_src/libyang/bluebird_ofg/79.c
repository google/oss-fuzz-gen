#include <string.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>  // Include for uint8_t
#include "libyang.h"  // Correct header file for libyang

int LLVMFuzzerTestOneInput_79(const uint8_t *data, size_t size) {
    if (data == NULL || size == 0) {
        // If the input data is null or size is zero, return immediately
        return 0;
    }

    struct ly_ctx *ctx = NULL;
    LY_ERR err;

    // Initialize the libyang context
    err = ly_ctx_new(NULL, 0, &ctx);
    if (err != LY_SUCCESS) {
        fprintf(stderr, "Failed to create context\n");
        return 0;
    }

    // Ensure the input data is null-terminated for safe string operations
    char *null_terminated_data = (char *)malloc(size + 1);
    if (!null_terminated_data) {
        ly_ctx_destroy(ctx);
        return 0;
    }
    memcpy(null_terminated_data, data, size);
    null_terminated_data[size] = '\0';

    // Attempt to parse the input data as a YANG module
    struct lys_module *module = NULL;
    err = lys_parse_mem(ctx, null_terminated_data, LYS_IN_YANG, &module);
    free(null_terminated_data);  // Free the allocated memory for null-terminated data

    if (err != LY_SUCCESS || !module) {
        // Commenting out the error message to avoid unnecessary stderr output during fuzzing
        // fprintf(stderr, "Failed to parse module\n");
        ly_ctx_destroy(ctx);
        return 0;
    }

    // Additional processing of the module can be added here if needed

    // Retrieve search directories to ensure the function is utilized
    const char *const *searchdirs = ly_ctx_get_searchdirs(ctx);
    if (searchdirs) {
        // Optionally, print or process search directories
    }

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

    LLVMFuzzerTestOneInput_79(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
