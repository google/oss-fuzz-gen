#include <stdint.h>
#include <stddef.h>
#include <zlib.h>

int LLVMFuzzerTestOneInput_128(const uint8_t *data, size_t size) {
    if (size < 1) {
        return 0;
    }

    z_stream stream;
    int windowBits = 15; // Default value for windowBits
    const char *version = ZLIB_VERSION;
    int stream_size = sizeof(z_stream);

    // Initialize the z_stream structure
    stream.zalloc = Z_NULL;
    stream.zfree = Z_NULL;
    stream.opaque = Z_NULL;
    stream.avail_in = size;
    stream.next_in = (Bytef *)data;

    // Call the function-under-test
    int result = inflateInit2_(&stream, windowBits, version, stream_size);

    if (result == Z_OK) {
        // Set up the output buffer
        uint8_t outbuffer[4096];
        stream.avail_out = sizeof(outbuffer);
        stream.next_out = outbuffer;

        // Inflate the data
        inflate(&stream, Z_NO_FLUSH);
    }

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

    LLVMFuzzerTestOneInput_128(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
