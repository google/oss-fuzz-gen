#include <stdint.h>
#include <stddef.h>
#include <zlib.h>

int LLVMFuzzerTestOneInput_33(const uint8_t *data, size_t size) {
    // Ensure we have enough data to extract the necessary parameters
    if (size < sizeof(int) * 2 + 1) {
        return 0;
    }

    // Initialize z_stream
    z_stream stream;
    stream.zalloc = Z_NULL;
    stream.zfree = Z_NULL;
    stream.opaque = Z_NULL;

    // Initialize the deflate stream
    if (deflateInit(&stream, Z_DEFAULT_COMPRESSION) != Z_OK) {
        return 0;
    }

    // Extract parameters for deflatePrime
    int bits = data[0] & 0x07; // Limit bits to 3 bits (0-7)
    int value = (data[1] << 8) | data[2]; // Use the next two bytes for value

    // Call the function-under-test
    deflatePrime(&stream, bits, value);

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

    LLVMFuzzerTestOneInput_33(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
