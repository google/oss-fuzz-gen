#include <sys/stat.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include "zlib.h"

int LLVMFuzzerTestOneInput_41(const uint8_t *data, size_t size) {
    // Ensure there is enough data to extract the integer for the second parameter
    if (size < sizeof(int)) {
        return 0;
    }

    // Initialize z_stream structure
    z_stream stream;
    stream.zalloc = Z_NULL;
    stream.zfree = Z_NULL;
    stream.opaque = Z_NULL;

    // Initialize the stream with inflateInit
    if (inflateInit(&stream) != Z_OK) {
        return 0;
    }

    // Extract an integer from the data for the second parameter
    int windowBits = *(const int*)data;

    // Call the function-under-test
    inflateReset2(&stream, windowBits);

    // Clean up
    inflateEnd(&stream);

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

    LLVMFuzzerTestOneInput_41(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
