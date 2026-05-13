#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "zlib.h"

static void initialize_stream(z_streamp strm) {
    memset(strm, 0, sizeof(z_stream));
    strm->zalloc = Z_NULL;
    strm->zfree = Z_NULL;
    strm->opaque = Z_NULL;
}

int LLVMFuzzerTestOneInput_9(const uint8_t *Data, size_t Size) {
    if (Size < 1) {
        return 0;
    }

    z_stream strm;
    initialize_stream(&strm);

    int level = Z_DEFAULT_COMPRESSION;
    int strategy = Z_DEFAULT_STRATEGY;
    int ret = deflateInit_(&strm, level, ZLIB_VERSION, sizeof(z_stream));
    if (ret != Z_OK) {
        return 0;
    }

    uint8_t *out = malloc(Size);
    if (!out) {
        deflateEnd(&strm);
        return 0;
    }

    strm.next_in = (z_const Bytef *)Data;
    strm.avail_in = Size;
    strm.next_out = out;
    strm.avail_out = Size;

    ret = deflate(&strm, Z_NO_FLUSH);
    if (ret != Z_OK && ret != Z_BUF_ERROR) {
        free(out);
        deflateEnd(&strm);
        return 0;
    }

    ret = deflateParams(&strm, Z_BEST_SPEED, Z_FILTERED);
    if (ret != Z_OK) {
        free(out);
        deflateEnd(&strm);
        return 0;
    }

    ret = deflate(&strm, Z_SYNC_FLUSH);
    if (ret != Z_OK && ret != Z_BUF_ERROR) {
        free(out);
        deflateEnd(&strm);
        return 0;
    }

    // Begin mutation: Producer.REPLACE_ARG_MUTATOR - Replaced argument 2 of deflateParams
    ret = deflateParams(&strm, Z_BEST_COMPRESSION, ZLIB_VER_MINOR);
    // End mutation: Producer.REPLACE_ARG_MUTATOR
    if (ret != Z_OK) {
        free(out);
        deflateEnd(&strm);
        return 0;
    }

    ret = deflate(&strm, Z_FINISH);
    if (ret != Z_STREAM_END && ret != Z_OK && ret != Z_BUF_ERROR) {
        free(out);
        deflateEnd(&strm);
        return 0;
    }

    ret = deflate(&strm, Z_FINISH);
    if (ret != Z_STREAM_END && ret != Z_OK && ret != Z_BUF_ERROR) {
        free(out);
        deflateEnd(&strm);
        return 0;
    }

    deflateEnd(&strm);
    free(out);
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

    LLVMFuzzerTestOneInput_9(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
