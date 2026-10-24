#include <stdint.h>
#include <stdlib.h>
#include <zlib.h>

int LLVMFuzzerTestOneInput_16(const uint8_t *data, size_t size) {
    // Ensure the data size is sufficient for extracting parameters
    if (size < 6) {
        return 0;
    }

    // Initialize z_stream structure
    z_stream stream;
    stream.zalloc = Z_NULL;
    stream.zfree = Z_NULL;
    stream.opaque = Z_NULL;

    // Extract parameters from the input data
    int level = data[0] % 10;  // Compression level (0-9)
    int method = data[1] % 2;  // Compression method (Z_DEFLATED)
    int windowBits = (data[2] % 16) + 8;  // Window size (8-15)
    int memLevel = (data[3] % 9) + 1;  // Memory level (1-9)
    int strategy = data[4] % 5;  // Strategy (Z_DEFAULT_STRATEGY, etc.)
    const char *version = ZLIB_VERSION;
    int stream_size = sizeof(z_stream);

    // Call the function-under-test
    int result = deflateInit2_(&stream, level, method, windowBits, memLevel, strategy, version, stream_size);

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

    LLVMFuzzerTestOneInput_16(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
