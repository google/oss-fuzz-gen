// This fuzz driver is generated for library zlib, aiming to fuzz the following functions:
// inflateInit2_ at inflate.c:173:13 in zlib.h
// inflate at inflate.c:474:13 in zlib.h
// inflateEnd at inflate.c:1155:13 in zlib.h
// inflateEnd at inflate.c:1155:13 in zlib.h
// inflateBackInit_ at infback.c:25:13 in zlib.h
// inflateBack at infback.c:191:13 in zlib.h
// inflateBackEnd at infback.c:572:13 in zlib.h
// inflateBackEnd at infback.c:572:13 in zlib.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <zlib.h>

static unsigned int dummy_in_func(void *in_desc, unsigned char **buffer) {
    *buffer = (unsigned char *)in_desc;
    return (unsigned int)strlen((char *)in_desc);
}

static int dummy_out_func(void *out_desc, unsigned char *buffer, unsigned len) {
    return len;
}

int LLVMFuzzerTestOneInput_6(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    z_stream strm;
    memset(&strm, 0, sizeof(z_stream));

    int ret;
    unsigned char window[32768];

    // Inflate process
    ret = inflateInit2_(&strm, 15, ZLIB_VERSION, sizeof(z_stream));
    if (ret != Z_OK) return 0;

    strm.next_in = (Bytef *)Data;
    strm.avail_in = (uInt)Size;

    unsigned char out[4096];
    strm.next_out = out;
    strm.avail_out = sizeof(out);

    ret = inflate(&strm, Z_FINISH);
    if (ret != Z_STREAM_END && ret != Z_OK) {
        inflateEnd(&strm);
        return 0;
    }

    inflateEnd(&strm);

    // InflateBack process
    ret = inflateBackInit_(&strm, 15, window, ZLIB_VERSION, sizeof(z_stream));
    if (ret != Z_OK) return 0;

    ret = inflateBack(&strm, dummy_in_func, (void *)Data, dummy_out_func, NULL);
    if (ret != Z_STREAM_END && ret != Z_OK) {
        inflateBackEnd(&strm);
        return 0;
    }

    inflateBackEnd(&strm);

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

    LLVMFuzzerTestOneInput_6(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
