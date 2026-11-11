#include <stdio.h>
#include <stdlib.h>
#include <string.h> // Include for memcpy
#include <libyang.h> // Correct header for libyang

int LLVMFuzzerTestOneInput_107(const uint8_t *data, size_t size) {
    const char *search_dir = NULL; // No specific search directory
    uint32_t options = 0; // Default options
    struct ly_ctx *ctx = NULL;
    LY_ERR err;

    // Allocate a buffer for the search directory string
    char *search_dir_buf = (char *)malloc(size + 1);
    if (!search_dir_buf) {
        return 0;
    }

    // Copy the fuzz data into the search directory buffer
    memcpy(search_dir_buf, data, size);
    search_dir_buf[size] = '\0'; // Null-terminate the string

    // Call the function-under-test
    err = ly_ctx_new(search_dir_buf, options, &ctx);

    // Check the result
    if (err == LY_SUCCESS) {
        // Successfully created the context, now destroy it
        ly_ctx_destroy(ctx);
    }

    // Free the allocated buffer
    free(search_dir_buf);

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

    LLVMFuzzerTestOneInput_107(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
