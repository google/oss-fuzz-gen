#include <sys/stat.h>
#include <string.h>
#include <iostream>
#include "sstream"
#include <string>
#include <vector>
#include "cstring"
#include "cstdlib"
#include <cstdio>
#include "cstdint"
#include <cstddef>
#include "tiffio.h"
#include "cstdint"
#include <cstdio>
#include "cstdlib"
#include "cstring"

static TIFF* createDummyTIFF(const uint8_t *Data, size_t Size) {
    FILE *file = fopen("./dummy_file", "wb");
    if (!file) return nullptr;
    fwrite(Data, 1, Size, file);
    fclose(file);

    TIFF *tif = TIFFOpen("./dummy_file", "rm");
    return tif;
}

static void cleanupTIFF(TIFF *tif) {
    if (tif) {
        TIFFClose(tif);
    }
    remove("./dummy_file");
}

extern "C" int LLVMFuzzerTestOneInput_68(const uint8_t *Data, size_t Size) {
    TIFF *tif = createDummyTIFF(Data, Size);
    if (!tif) return 0;

    uint32_t strile = 0;
    uint32_t strip = 0;
    int pbErr = 0;

    // Fuzz TIFFGetStrileByteCount
    uint64_t strileByteCount = TIFFGetStrileByteCount(tif, strile);

    // Fuzz TIFFStripSize64
    uint64_t stripSize64 = TIFFStripSize64(tif);

    // Fuzz TIFFRawStripSize64
    uint64_t rawStripSize64 = TIFFRawStripSize64(tif, strip);

    // Fuzz TIFFGetStrileByteCountWithErr
    uint64_t strileByteCountWithErr = TIFFGetStrileByteCountWithErr(tif, strile, &pbErr);

    // Fuzz TIFFGetStrileOffset
    uint64_t strileOffset = TIFFGetStrileOffset(tif, strile);

    // Fuzz TIFFScanlineSize64
    uint64_t scanlineSize64 = TIFFScanlineSize64(tif);

    cleanupTIFF(tif);
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

    LLVMFuzzerTestOneInput_68(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
