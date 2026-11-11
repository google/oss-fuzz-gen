#include <sys/stat.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include "zlib.h"

int LLVMFuzzerTestOneInput_5(const uint8_t *data, size_t size) {
    // Initialize a z_stream structure
    z_stream stream;
    stream.zalloc = Z_NULL;
    stream.zfree = Z_NULL;
    stream.opaque = Z_NULL;
    stream.next_in = Z_NULL;
    stream.avail_in = 0;

    // Initialize the stream for inflation
    if (inflateInit(&stream) != Z_OK) {
        return 0;
    }

    // Set the input data for the stream
    stream.next_in = (Bytef *)data;
    stream.avail_in = (uInt)size;

    // Allocate a buffer for the output
    unsigned char outbuffer[32768];
    stream.next_out = outbuffer;
    stream.avail_out = sizeof(outbuffer);

    // Inflate the data
    while (stream.avail_in != 0) {
        int ret = inflate(&stream, Z_NO_FLUSH);
        if (ret == Z_STREAM_END) {
                break;
        }
        if (ret != Z_OK) {
            // Begin mutation: Producer.REPLACE_FUNC_MUTATOR - Replaced function inflateEnd with inflateSync
            inflateSync(&stream);
            // End mutation: Producer.REPLACE_FUNC_MUTATOR
            return 0;
        }
    }

    // Call the function-under-test
    long markResult = inflateMark(&stream);

    // Clean up and free the stream
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

    LLVMFuzzerTestOneInput_5(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
