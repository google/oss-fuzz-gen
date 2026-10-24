#include <stdint.h>
#include <stddef.h>
#include <zlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput_109(const uint8_t *data, size_t size) {
    if (size < 1) return 0;

    z_stream stream;
    memset(&stream, 0, sizeof(z_stream));

    // Ensure that version is not NULL and has a valid value
    const char *version = ZLIB_VERSION;
    int stream_size = (int)sizeof(z_stream);

    // Initialize the zlib stream for decompression
    int result = inflateInit_(&stream, version, stream_size);
    if (result != Z_OK) {
        return 0;
    }

    // Set the input data for decompression
    stream.next_in = (Bytef *)data;
    stream.avail_in = size;

    // Allocate a buffer for the decompressed output
    uint8_t outbuffer[4096];
    stream.next_out = outbuffer;
    stream.avail_out = sizeof(outbuffer);

    // Perform the decompression
    inflate(&stream, Z_NO_FLUSH);

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

    LLVMFuzzerTestOneInput_109(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
