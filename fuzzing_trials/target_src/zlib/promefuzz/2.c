// This fuzz driver is generated for library zlib, aiming to fuzz the following functions:
// inflateInit_ at inflate.c:214:13 in zlib.h
// inflatePrime at inflate.c:219:13 in zlib.h
// inflateSync at inflate.c:1264:13 in zlib.h
// inflate at inflate.c:474:13 in zlib.h
// inflateSync at inflate.c:1264:13 in zlib.h
// inflateSyncPoint at inflate.c:1320:13 in zlib.h
// inflateCopy at inflate.c:1328:13 in zlib.h
// inflateEnd at inflate.c:1155:13 in zlib.h
// inflateUndermine at inflate.c:1370:13 in zlib.h
// inflateMark at inflate.c:1397:14 in zlib.h
// inflateEnd at inflate.c:1155:13 in zlib.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>

static void initialize_stream(z_stream *strm) {
    memset(strm, 0, sizeof(z_stream));
    strm->zalloc = Z_NULL;
    strm->zfree = Z_NULL;
    strm->opaque = Z_NULL;
}

int LLVMFuzzerTestOneInput_2(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    z_stream strm;
    initialize_stream(&strm);

    Bytef out_buffer[1024];
    strm.next_in = (z_const Bytef *)Data;
    strm.avail_in = (uInt)Size;
    strm.next_out = out_buffer;
    strm.avail_out = sizeof(out_buffer);

    int ret = inflateInit(&strm);
    if (ret != Z_OK) return 0;

    // inflatePrime
    inflatePrime(&strm, 1, Data[0] & 1);

    // inflateSync
    inflateSync(&strm);

    // inflate
    ret = inflate(&strm, Z_NO_FLUSH);

    // inflateSync again
    inflateSync(&strm);

    // inflateSyncPoint
    inflateSyncPoint(&strm);

    // inflateCopy
    z_stream strm_copy;
    initialize_stream(&strm_copy);
    inflateCopy(&strm_copy, &strm);
    inflateEnd(&strm_copy);

    // inflateUndermine
    inflateUndermine(&strm, 1);

    // inflateMark
    inflateMark(&strm);

    // inflateEnd
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

    LLVMFuzzerTestOneInput_2(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
