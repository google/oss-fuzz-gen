#include <stdint.h>
#include <stdlib.h>
#include <zlib.h>

int LLVMFuzzerTestOneInput_74(const uint8_t *data, size_t size) {
    z_stream source_stream;
    z_stream dest_stream;
    int ret;

    // Initialize source_stream
    source_stream.zalloc = Z_NULL;
    source_stream.zfree = Z_NULL;
    source_stream.opaque = Z_NULL;
    source_stream.next_in = (Bytef *)data;
    source_stream.avail_in = (uInt)size;

    // Initialize dest_stream
    dest_stream.zalloc = Z_NULL;
    dest_stream.zfree = Z_NULL;
    dest_stream.opaque = Z_NULL;
    dest_stream.next_in = Z_NULL;
    dest_stream.avail_in = 0;

    // Initialize the source stream for inflation
    ret = inflateInit(&source_stream);
    if (ret != Z_OK) {
        return 0;
    }

    // Initialize the dest stream for inflation
    ret = inflateInit(&dest_stream);
    if (ret != Z_OK) {
        inflateEnd(&source_stream);
        return 0;
    }

    // Call the function-under-test
    inflateCopy(&dest_stream, &source_stream);

    // Clean up
    inflateEnd(&source_stream);
    inflateEnd(&dest_stream);

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

    LLVMFuzzerTestOneInput_74(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
