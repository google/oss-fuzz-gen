#include <stdint.h>
#include <stddef.h>
#include <zlib.h>

int LLVMFuzzerTestOneInput_139(const uint8_t *data, size_t size) {
    z_stream stream;
    int ret;

    // Initialize the z_stream structure
    stream.zalloc = Z_NULL;
    stream.zfree = Z_NULL;
    stream.opaque = Z_NULL;
    stream.avail_in = 0;
    stream.next_in = Z_NULL;

    // Initialize inflate state
    ret = inflateInit(&stream);
    if (ret != Z_OK) {
        return 0;
    }

    // Set input data
    stream.avail_in = size;
    stream.next_in = (Bytef *)data;

    // Allocate a buffer for output
    unsigned char outbuffer[1024];
    stream.avail_out = sizeof(outbuffer);
    stream.next_out = outbuffer;

    // Perform inflation
    inflate(&stream, Z_NO_FLUSH);

    // Call the function-under-test
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

    LLVMFuzzerTestOneInput_139(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
