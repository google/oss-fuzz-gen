#include <sys/stat.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include "zlib.h"

#ifdef __cplusplus
extern "C" {
#endif

int LLVMFuzzerTestOneInput_8(const uint8_t *data, size_t size) {
    z_stream source_stream;
    z_stream dest_stream;
    int result;

    // Initialize the source stream
    source_stream.zalloc = Z_NULL;
    source_stream.zfree = Z_NULL;
    source_stream.opaque = Z_NULL;
    source_stream.avail_in = size;
    source_stream.next_in = (Bytef *)data;

    // Initialize the destination stream
    dest_stream.zalloc = Z_NULL;
    dest_stream.zfree = Z_NULL;
    dest_stream.opaque = Z_NULL;
    dest_stream.avail_in = 0;
    dest_stream.next_in = Z_NULL;

    // Initialize the source stream for deflation
    if (deflateInit(&source_stream, Z_DEFAULT_COMPRESSION) != Z_OK) {
        return 0;
    }

    // Call deflateCopy with the initialized streams
    result = deflateCopy(&dest_stream, &source_stream);

    // Clean up
    deflateEnd(&source_stream);
    deflateEnd(&dest_stream);

    return 0;
}

#ifdef __cplusplus
}
#endif
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

    LLVMFuzzerTestOneInput_8(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
