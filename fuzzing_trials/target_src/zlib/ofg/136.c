#include <stdint.h>
#include <stddef.h>
#include <zlib.h>

int LLVMFuzzerTestOneInput_136(const uint8_t *data, size_t size) {
    // Ensure that the input data is large enough to initialize z_stream
    if (size < sizeof(z_stream)) {
        return 0;
    }

    // Initialize a z_stream structure
    z_stream stream;
    stream.next_in = (Bytef *)data;
    stream.avail_in = (uInt)size;
    stream.zalloc = Z_NULL;
    stream.zfree = Z_NULL;
    stream.opaque = Z_NULL;

    // Call inflateInit to initialize the stream for inflation
    if (inflateInit(&stream) != Z_OK) {
        return 0;
    }

    // Call the function-under-test
    int result = inflateReset(&stream);

    // Clean up
    inflateEnd(&stream);

    return result;
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

    LLVMFuzzerTestOneInput_136(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
