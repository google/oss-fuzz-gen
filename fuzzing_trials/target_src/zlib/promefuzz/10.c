// This fuzz driver is generated for library zlib, aiming to fuzz the following functions:
// inflateInit2_ at inflate.c:173:13 in zlib.h
// inflate at inflate.c:474:13 in zlib.h
// crc32 at crc32.c:946:15 in zlib.h
// crc32_combine at crc32.c:981:15 in zlib.h
// inflateReset at inflate.c:125:13 in zlib.h
// inflateEnd at inflate.c:1155:13 in zlib.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdio.h>
#include <stdlib.h>
#include <zlib.h>
#include <stdint.h>

static void write_dummy_file(const uint8_t *Data, size_t Size) {
    FILE *file = fopen("./dummy_file", "wb");
    if (file) {
        fwrite(Data, 1, Size, file);
        fclose(file);
    }
}

int LLVMFuzzerTestOneInput_10(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    z_stream strm;
    int ret;
    uLong crc1 = 0, crc2 = 0;
    z_off_t len2 = 0;
    int windowBits = 15; // Default window size
    int flush = Z_NO_FLUSH; // Default flush mode

    // Initialize the z_stream structure
    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;

    // Initialize the inflate process
    ret = inflateInit2_(&strm, windowBits, ZLIB_VERSION, sizeof(z_stream));
    if (ret != Z_OK) return 0;

    // Set input data for inflation
    strm.next_in = (Bytef *)Data;
    strm.avail_in = Size;

    // Prepare output buffer
    unsigned char out[1024];
    strm.next_out = out;
    strm.avail_out = sizeof(out);

    // Perform inflation
    ret = inflate(&strm, flush);
    if (ret != Z_STREAM_ERROR) {
        // Combine CRCs if inflate succeeded
        crc2 = crc32(0L, Z_NULL, 0);
        uLong combined_crc = crc32_combine(crc1, crc2, len2);

        // Reset the inflate stream
        ret = inflateReset(&strm);
    }

    // Clean up the inflate stream
    ret = inflateEnd(&strm);

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

    LLVMFuzzerTestOneInput_10(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
