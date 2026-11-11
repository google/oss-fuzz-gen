#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <zlib.h>

int LLVMFuzzerTestOneInput_15(const uint8_t *data, size_t size) {
    if (size < 1) return 0;

    z_stream stream;
    memset(&stream, 0, sizeof(stream));

    int level = Z_DEFAULT_COMPRESSION;
    int method = Z_DEFLATED;
    int windowBits = 15; // Default window size
    int memLevel = 8; // Default memory level
    int strategy = Z_DEFAULT_STRATEGY;
    const char *version = ZLIB_VERSION;
    int stream_size = sizeof(z_stream);

    // Ensure that we have enough data to extract meaningful parameters
    if (size > 5) {
        level = data[0] % 10; // Compression level between 0-9
        method = data[1] % 2; // Method (0 or 1)
        windowBits = 8 + (data[2] % 8); // Window bits between 8-15
        memLevel = 1 + (data[3] % 9); // Memory level between 1-9
        strategy = data[4] % 5; // Strategy between 0-4
    }

    deflateInit2_(&stream, level, method, windowBits, memLevel, strategy, version, stream_size);

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

    LLVMFuzzerTestOneInput_15(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
