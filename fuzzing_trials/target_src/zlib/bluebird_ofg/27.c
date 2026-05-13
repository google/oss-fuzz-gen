#include <sys/stat.h>
#include <stdint.h>
#include <stdlib.h>
#include "zlib.h"
#include <string.h>

// Declare the external function
extern int inflateUndermine(z_streamp strm, int subvert);

int LLVMFuzzerTestOneInput_27(const uint8_t *data, size_t size) {
    // Ensure the data is not NULL and has a size
    if (data == NULL || size == 0) {
        return 0;
    }

    // Initialize the z_stream structure
    z_stream strm;
    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;
    strm.next_in = Z_NULL;
    strm.avail_in = 0;

    // Initialize inflate state
    if (inflateInit(&strm) != Z_OK) {
        return 0;
    }

    // Allocate an output buffer
    size_t out_buffer_size = size * 2; // Assume the output might be larger
    uint8_t *out_buffer = (uint8_t *)malloc(out_buffer_size);
    if (out_buffer == NULL) {
        inflateEnd(&strm);
        return 0;
    }

    // Set the input data
    strm.next_in = (Bytef *)data;
    strm.avail_in = (uInt)size;
    strm.next_out = out_buffer;
    strm.avail_out = (uInt)out_buffer_size;

    // Call the function-under-test with a non-NULL z_streamp and a non-zero integer
    int result = inflateUndermine(&strm, 1);

    // Check if inflateUndermine processed any input
    while (result == Z_OK || result == Z_BUF_ERROR) {
        // If the output buffer is full, expand it
        if (strm.avail_out == 0) {
            size_t new_out_buffer_size = out_buffer_size * 2;
            uint8_t *new_out_buffer = (uint8_t *)realloc(out_buffer, new_out_buffer_size);
            if (new_out_buffer == NULL) {
                free(out_buffer);
                inflateEnd(&strm);
                return 0;
            }
            out_buffer = new_out_buffer;
            strm.next_out = out_buffer + out_buffer_size;
            strm.avail_out = (uInt)(new_out_buffer_size - out_buffer_size);
            out_buffer_size = new_out_buffer_size;
        }
        result = inflateUndermine(&strm, 1);
    }

    // Clean up and free resources
    free(out_buffer);
    inflateEnd(&strm);

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

    LLVMFuzzerTestOneInput_27(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
