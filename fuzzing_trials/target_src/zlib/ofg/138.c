#include <stdint.h>
#include <stddef.h>
#include <zlib.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput_138(const uint8_t *data, size_t size) {
    // Declare a z_stream structure
    z_stream stream;
    
    // Initialize the z_stream structure
    stream.zalloc = Z_NULL;
    stream.zfree = Z_NULL;
    stream.opaque = Z_NULL;
    stream.avail_in = (uInt)size;
    stream.next_in = (Bytef *)data;

    // Initialize the inflate state
    if (inflateInit(&stream) != Z_OK) {
        return 0;
    }

    // Allocate a buffer for the decompressed data
    size_t buffer_size = size * 2; // Start with a buffer twice the size of the input
    Bytef *out_buffer = (Bytef *)malloc(buffer_size);
    if (!out_buffer) {
        inflateEnd(&stream);
        return 0;
    }

    stream.avail_out = (uInt)buffer_size;
    stream.next_out = out_buffer;

    // Inflate the data
    while (stream.avail_in != 0) {
        int ret = inflate(&stream, Z_NO_FLUSH);
        if (ret == Z_STREAM_END) break; // End of stream
        if (ret != Z_OK) {
            // If the buffer is not enough, increase the buffer size
            buffer_size *= 2;
            out_buffer = (Bytef *)realloc(out_buffer, buffer_size);
            if (!out_buffer) {
                inflateEnd(&stream);
                return 0;
            }
            stream.avail_out = (uInt)(buffer_size - (stream.total_out));
            stream.next_out = out_buffer + stream.total_out;
        }
    }

    // Clean up
    free(out_buffer);
    int result = inflateEnd(&stream);

    // Return the result of inflateEnd
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

    LLVMFuzzerTestOneInput_138(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
