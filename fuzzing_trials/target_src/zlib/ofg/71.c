#include <stdint.h>
#include <stdlib.h>
#include <zlib.h>

int LLVMFuzzerTestOneInput_71(const uint8_t *data, size_t size) {
    // Initialize z_stream structure
    z_stream strm;
    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;
    strm.avail_in = 0;
    strm.next_in = Z_NULL;

    // Initialize gz_header structure
    gz_header header;
    header.text = 0;
    header.time = 0;
    header.xflags = 0;
    header.os = 0;
    header.extra = NULL;
    header.extra_len = 0;
    header.extra_max = 0;
    header.name = NULL;
    header.name_max = 0;
    header.comment = NULL;
    header.comm_max = 0;
    header.hcrc = 0;
    header.done = 0;

    // Initialize inflate state
    if (inflateInit2(&strm, 15 + 32) != Z_OK) {
        return 0;
    }

    // Set input data
    strm.avail_in = size;
    strm.next_in = (Bytef *)data;

    // Call the function-under-test
    inflateGetHeader(&strm, &header);

    // Clean up
    inflateEnd(&strm);

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

    LLVMFuzzerTestOneInput_71(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
