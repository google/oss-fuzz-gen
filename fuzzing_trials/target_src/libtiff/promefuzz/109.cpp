// This fuzz driver is generated for library libtiff, aiming to fuzz the following functions:
// TIFFOpen at tif_unix.c:232:7 in tiffio.h
// TIFFStripSize64 at tif_strip.c:196:10 in tiffio.h
// TIFFVTileSize64 at tif_tile.c:188:10 in tiffio.h
// TIFFTileSize64 at tif_tile.c:249:10 in tiffio.h
// TIFFVStripSize64 at tif_strip.c:88:10 in tiffio.h
// TIFFTileRowSize64 at tif_tile.c:140:10 in tiffio.h
// TIFFScanlineSize64 at tif_strip.c:257:10 in tiffio.h
// TIFFClose at tif_close.c:155:6 in tiffio.h
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <cstdint>
#include <cstddef>
#include <tiffio.h>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>

static TIFF* initializeTIFF(const uint8_t* Data, size_t Size) {
    FILE* file = fopen("./dummy_file", "wb");
    if (!file) return nullptr;

    if (fwrite(Data, 1, Size, file) != Size) {
        fclose(file);
        return nullptr;
    }
    fclose(file);

    TIFF* tif = TIFFOpen("./dummy_file", "r");
    return tif;
}

extern "C" int LLVMFuzzerTestOneInput_109(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    TIFF* tif = initializeTIFF(Data, Size);
    if (!tif) return 0;

    // Test TIFFStripSize64
    uint64_t stripSize = TIFFStripSize64(tif);

    // Test TIFFVTileSize64 with a random row count
    uint32_t nrows = static_cast<uint32_t>(Data[0]);
    uint64_t vTileSize = TIFFVTileSize64(tif, nrows);

    // Test TIFFTileSize64
    uint64_t tileSize = TIFFTileSize64(tif);

    // Test TIFFVStripSize64 with a random row count
    uint64_t vStripSize = TIFFVStripSize64(tif, nrows);

    // Test TIFFTileRowSize64
    uint64_t tileRowSize = TIFFTileRowSize64(tif);

    // Test TIFFScanlineSize64
    uint64_t scanlineSize = TIFFScanlineSize64(tif);

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

        LLVMFuzzerTestOneInput_109(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    