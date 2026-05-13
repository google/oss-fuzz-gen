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
#include "cstdint"
#include <cstdio>
#include "cstdlib"
#include "cstring"
#include "tiffio.h"

static TIFF* createDummyTIFF() {
    // Create a dummy TIFF structure with minimal initialization
    TIFF* tif = TIFFOpen("./dummy_file", "w");
    if (!tif) return nullptr;

    // Set some basic tags to avoid errors
    TIFFSetField(tif, TIFFTAG_IMAGEWIDTH, 1);
    TIFFSetField(tif, TIFFTAG_IMAGELENGTH, 1);
    TIFFSetField(tif, TIFFTAG_BITSPERSAMPLE, 8);
    TIFFSetField(tif, TIFFTAG_SAMPLESPERPIXEL, 1);
    TIFFSetField(tif, TIFFTAG_PLANARCONFIG, PLANARCONFIG_CONTIG);
    TIFFSetField(tif, TIFFTAG_ROWSPERSTRIP, 1);

    return tif;
}

extern "C" int LLVMFuzzerTestOneInput_71(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(uint64_t)) return 0; // Ensure there's enough data for an offset

    // Create a dummy TIFF file
    TIFF* tif = createDummyTIFF();
    if (!tif) return 0;

    // Use the first 8 bytes as an offset
    uint64_t offset;
    memcpy(&offset, Data, sizeof(offset));

    // Fuzz TIFFSetSubDirectory
    TIFFSetSubDirectory(tif, offset);

    // Fuzz TIFFStripSize64
    uint64_t stripSize = TIFFStripSize64(tif);

    // Fuzz TIFFTileSize64
    uint64_t tileSize = TIFFTileSize64(tif);

    // Fuzz TIFFCurrentDirOffset
    uint64_t currentDirOffset = TIFFCurrentDirOffset(tif);

    // Fuzz TIFFTileRowSize64
    uint64_t tileRowSize = TIFFTileRowSize64(tif);

    // Fuzz TIFFScanlineSize64
    uint64_t scanlineSize = TIFFScanlineSize64(tif);

    // Clean up
    TIFFClose(tif);

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
