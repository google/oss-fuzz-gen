// This fuzz driver is generated for library zlib, aiming to fuzz the following functions:
// deflateInit_ at deflate.c:379:13 in zlib.h
// deflateEnd at deflate.c:1293:13 in zlib.h
// inflateInit_ at inflate.c:214:13 in zlib.h
// inflateEnd at inflate.c:1155:13 in zlib.h
// deflateReset at deflate.c:704:13 in zlib.h
// inflateReset at inflate.c:125:13 in zlib.h
// deflateReset at deflate.c:704:13 in zlib.h
// inflateEnd at inflate.c:1155:13 in zlib.h
// deflateEnd at deflate.c:1293:13 in zlib.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <zlib.h>

static void handle_deflate(z_stream *strm, const uint8_t *Data, size_t Size) {
    int ret = deflateInit_(strm, Z_DEFAULT_COMPRESSION, ZLIB_VERSION, sizeof(z_stream));
    if (ret != Z_OK) return;

    strm->next_in = (z_const Bytef *)Data;
    strm->avail_in = (uInt)Size;
    strm->next_out = (Bytef *)malloc(Size);
    strm->avail_out = (uInt)Size;

    deflateEnd(strm);
    free(strm->next_out);
}

static void handle_inflate(z_stream *strm, const uint8_t *Data, size_t Size) {
    int ret = inflateInit_(strm, ZLIB_VERSION, sizeof(z_stream));
    if (ret != Z_OK) return;

    strm->next_in = (z_const Bytef *)Data;
    strm->avail_in = (uInt)Size;
    strm->next_out = (Bytef *)malloc(Size);
    strm->avail_out = (uInt)Size;

    inflateEnd(strm);
    free(strm->next_out);
}

static void reset_and_test(z_stream *strm) {
    deflateReset(strm);
    inflateReset(strm);
    deflateReset(strm);
    inflateEnd(strm);
    deflateEnd(strm);
}

int LLVMFuzzerTestOneInput_3(const uint8_t *Data, size_t Size) {
    if (Size == 0) return 0;

    z_stream strm;
    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;

    handle_deflate(&strm, Data, Size);
    handle_inflate(&strm, Data, Size);
    reset_and_test(&strm);

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

    LLVMFuzzerTestOneInput_3(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
