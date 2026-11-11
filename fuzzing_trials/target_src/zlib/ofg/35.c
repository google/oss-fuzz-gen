#include <stdint.h>
#include <stddef.h>
#include <zlib.h>
#include <string.h> // Include for memcpy

int LLVMFuzzerTestOneInput_35(const uint8_t *data, size_t size) {
    z_stream stream;
    int ret;
    Bytef *dictionary;
    uInt dictLength;

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

    // Ensure size is not zero for dictionary
    if (size == 0) {
        inflateEnd(&stream);
        return 0;
    }

    // Use the input data as the dictionary
    dictionary = (Bytef *)data;
    dictLength = (uInt)size;

    // Call the function-under-test
    inflateSetDictionary(&stream, dictionary, dictLength);

    // Prepare a buffer for decompression output
    unsigned char out[4096];
    stream.avail_out = sizeof(out);
    stream.next_out = out;

    // Use the input data as compressed data for decompression
    stream.avail_in = size;
    stream.next_in = (Bytef *)data;

    // Perform a decompression operation
    ret = inflate(&stream, Z_NO_FLUSH);

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

    LLVMFuzzerTestOneInput_35(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
