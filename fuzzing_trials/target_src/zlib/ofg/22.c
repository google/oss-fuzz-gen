#include <stdint.h>
#include <stddef.h>
#include <zlib.h>

// Remove extern "C" as it is not needed in a C file
int LLVMFuzzerTestOneInput_22(const uint8_t *data, size_t size) {
    // Ensure there is enough data to initialize the fields
    if (size < 10) {
        return 0;
    }

    // Initialize z_stream structure
    z_stream stream;
    stream.zalloc = Z_NULL;
    stream.zfree = Z_NULL;
    stream.opaque = Z_NULL;

    // Initialize gz_header structure
    gz_header header;
    header.text = data[0];
    header.time = *(uint32_t *)(data + 1);
    header.xflags = data[5];
    header.os = data[6];
    header.extra = (size > 10) ? (Bytef *)(data + 7) : NULL;
    header.extra_len = (size > 10) ? (uInt)(size - 7) : 0;
    header.extra_max = header.extra_len;
    header.name = NULL;
    header.comment = NULL;
    header.hcrc = 0;
    header.done = 0;

    // Call the function-under-test
    deflateSetHeader(&stream, &header);

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

    LLVMFuzzerTestOneInput_22(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
