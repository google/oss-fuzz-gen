#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include "zlib.h"
#include <string.h>

int LLVMFuzzerTestOneInput_45(const uint8_t *data, size_t size) {
    if (size < 1) return 0; // Ensure there is at least one byte for windowBits

    z_stream stream;
    memset(&stream, 0, sizeof(stream));

    int windowBits = data[0] % 16 + 8; // Valid range for windowBits is 8 to 15

    // Use a constant string for the version parameter
    const char *version = ZLIB_VERSION;
    int stream_size = (int)sizeof(z_stream);

    // Call the function-under-test
    int result = inflateInit2_(&stream, windowBits, version, stream_size);

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

    LLVMFuzzerTestOneInput_45(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
