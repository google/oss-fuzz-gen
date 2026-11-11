// This fuzz driver is generated for library zlib, aiming to fuzz the following functions:
// inflateInit2_ at inflate.c:173:13 in zlib.h
// inflateGetHeader at inflate.c:1219:13 in zlib.h
// inflateEnd at inflate.c:1155:13 in zlib.h
// inflate at inflate.c:474:13 in zlib.h
// inflateEnd at inflate.c:1155:13 in zlib.h
// inflateSetDictionary at inflate.c:1187:13 in zlib.h
// inflateSetDictionary at inflate.c:1187:13 in zlib.h
// inflateSetDictionary at inflate.c:1187:13 in zlib.h
// inflate at inflate.c:474:13 in zlib.h
// inflateEnd at inflate.c:1155:13 in zlib.h
// inflateCopy at inflate.c:1328:13 in zlib.h
// inflateEnd at inflate.c:1155:13 in zlib.h
// inflateEnd at inflate.c:1155:13 in zlib.h
// inflateReset2 at inflate.c:136:13 in zlib.h
// inflateEnd at inflate.c:1155:13 in zlib.h
// inflateEnd at inflate.c:1155:13 in zlib.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdio.h>
#include <stdlib.h>
#include <zlib.h>

static void init_stream(z_stream *strm) {
    strm->zalloc = Z_NULL;
    strm->zfree = Z_NULL;
    strm->opaque = Z_NULL;
}

int LLVMFuzzerTestOneInput_8(const uint8_t *Data, size_t Size) {
    z_stream strm;
    gz_header header;
    int ret;
    Bytef out[4096];
    Bytef dictionary[32] = {0};

    // Initialize the stream
    init_stream(&strm);

    // Initialize inflate with windowBits
    ret = inflateInit2_(&strm, 15, ZLIB_VERSION, sizeof(z_stream));
    if (ret != Z_OK) return 0;

    // Set up the header
    ret = inflateGetHeader(&strm, &header);
    if (ret != Z_OK) {
        inflateEnd(&strm);
        return 0;
    }

    // Set input data
    strm.next_in = (Bytef *)Data;
    strm.avail_in = Size;
    strm.next_out = out;
    strm.avail_out = sizeof(out);

    // Inflate the data
    ret = inflate(&strm, Z_NO_FLUSH);
    if (ret != Z_STREAM_END && ret != Z_OK) {
        inflateEnd(&strm);
        return 0;
    }

    // Set dictionary multiple times
    inflateSetDictionary(&strm, dictionary, sizeof(dictionary));
    inflateSetDictionary(&strm, dictionary, sizeof(dictionary));
    inflateSetDictionary(&strm, dictionary, sizeof(dictionary));

    // Inflate again
    strm.next_out = out;
    strm.avail_out = sizeof(out);
    ret = inflate(&strm, Z_FINISH);
    if (ret != Z_STREAM_END && ret != Z_OK) {
        inflateEnd(&strm);
        return 0;
    }

    // Copy the inflate state
    z_stream strm_copy;
    init_stream(&strm_copy);
    ret = inflateCopy(&strm_copy, &strm);
    if (ret != Z_OK) {
        inflateEnd(&strm);
        return 0;
    }

    // End the original stream
    inflateEnd(&strm);

    // Reset the copied stream with a new window size
    ret = inflateReset2(&strm_copy, 15);
    if (ret != Z_OK) {
        inflateEnd(&strm_copy);
        return 0;
    }

    // End the copied stream
    inflateEnd(&strm_copy);

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

    LLVMFuzzerTestOneInput_8(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
