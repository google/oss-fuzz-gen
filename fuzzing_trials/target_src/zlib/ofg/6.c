#include <zlib.h>
#include <stdint.h>
#include <stddef.h>

int LLVMFuzzerTestOneInput_6(const uint8_t *data, size_t size) {
    z_stream stream;
    uLong sourceLen;

    // Initialize z_stream structure
    stream.zalloc = Z_NULL;
    stream.zfree = Z_NULL;
    stream.opaque = Z_NULL;

    // Ensure size is not zero to avoid division by zero
    if (size == 0) {
        return 0;
    }

    // Use the size as an arbitrary value for sourceLen
    sourceLen = (uLong)size;

    // Initialize the stream for compression
    if (deflateInit(&stream, Z_DEFAULT_COMPRESSION) != Z_OK) {
        return 0;
    }

    // Call the function-under-test
    uLong bound = deflateBound(&stream, sourceLen);

    // Use the result in some way to avoid compiler optimizations
    (void)bound;

    // Clean up the z_stream
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

    LLVMFuzzerTestOneInput_6(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
