#include <stddef.h>
#include <stdint.h>
#include <zlib.h>

int LLVMFuzzerTestOneInput_46(const uint8_t *data, size_t size) {
    z_stream stream;
    int level;
    const char *version;
    int stream_size;
    int result;

    // Initialize z_stream structure
    stream.zalloc = Z_NULL;
    stream.zfree = Z_NULL;
    stream.opaque = Z_NULL;

    // Ensure size is sufficient for accessing data safely
    if (size < 4) {
        return 0;
    }

    // Extract level from data
    level = data[0] % 10; // Compression level between 0-9

    // Set version to a known valid version string
    version = ZLIB_VERSION;

    // Extract stream_size from data
    stream_size = data[1];

    // Call the function-under-test
    result = deflateInit_(&stream, level, version, stream_size);

    // Clean up the z_stream if initialized successfully
    if (result == Z_OK) {
        deflateEnd(&stream);
    }

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

    LLVMFuzzerTestOneInput_46(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
