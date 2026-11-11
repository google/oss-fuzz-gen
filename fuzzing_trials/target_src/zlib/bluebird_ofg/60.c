#include <sys/stat.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include "zlib.h"

int LLVMFuzzerTestOneInput_60(const uint8_t *data, size_t size) {
    // Initialize a z_stream structure
    z_stream stream;
    stream.zalloc = Z_NULL;
    stream.zfree = Z_NULL;
    stream.opaque = Z_NULL;

    // Initialize the deflate process
    if (deflateInit(&stream, Z_DEFAULT_COMPRESSION) != Z_OK) {
        return 0;
    }

    // Ensure size is large enough to extract two integers
    if (size < 2) {
        deflateEnd(&stream);
        return 0;
    }

    // Extract two integers from the data
    int param1 = data[0] % 10; // Compression level (0-9)
    int param2 = data[1] % 10; // Strategy (0-9)

    // Call the function-under-test
    deflateParams(&stream, param1, param2);

    // Clean up
    deflateEnd(&stream);

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

    LLVMFuzzerTestOneInput_60(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
