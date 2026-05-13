// This fuzz driver is generated for library libtiff, aiming to fuzz the following functions:
// TIFFOpen at tif_unix.c:232:7 in tiffio.h
// TIFFSwabLong8 at tif_swab.c:60:6 in tiffio.h
// TIFFTileSize64 at tif_tile.c:249:10 in tiffio.h
// TIFFScanlineSize64 at tif_strip.c:257:10 in tiffio.h
// TIFFSetSubDirectory at tif_dir.c:2163:5 in tiffio.h
// TIFFReadGPSDirectory at tif_dirread.c:5564:5 in tiffio.h
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
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <tiffio.h>

extern "C" int LLVMFuzzerTestOneInput_48(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(uint64_t)) {
        return 0;
    }

    // Prepare a buffer to use with TIFFReadScanline
    void *buffer = malloc(Size);
    if (!buffer) {
        return 0;
    }

    // Create a dummy TIFF structure
    TIFF *tif = TIFFOpen("./dummy_file", "w");
    if (!tif) {
        free(buffer);
        return 0;
    }

    // Prepare a uint64_t for TIFFSwabLong8
    uint64_t swabValue;
    memcpy(&swabValue, Data, sizeof(uint64_t));

    // Call TIFFSwabLong8
    TIFFSwabLong8(&swabValue);

    // Call TIFFTileSize64
    uint64_t tileSize = TIFFTileSize64(tif);

    // Call TIFFScanlineSize64
    uint64_t scanlineSize = TIFFScanlineSize64(tif);

    // Call TIFFReadScanline
    if (Size >= sizeof(uint32_t) + sizeof(uint16_t)) {
        uint32_t row;
        uint16_t sample;
        memcpy(&row, Data, sizeof(uint32_t));
        memcpy(&sample, Data + sizeof(uint32_t), sizeof(uint16_t));
        TIFFReadScanline(tif, buffer, row, sample);
    }

    // Call TIFFSetSubDirectory
    if (Size >= sizeof(uint64_t)) {
        uint64_t subDirectoryOffset;
        memcpy(&subDirectoryOffset, Data, sizeof(uint64_t));
        TIFFSetSubDirectory(tif, subDirectoryOffset);
    }

    // Call TIFFReadGPSDirectory
    if (Size >= sizeof(toff_t)) {
        toff_t gpsDirectoryOffset;
        memcpy(&gpsDirectoryOffset, Data, sizeof(toff_t));
        TIFFReadGPSDirectory(tif, gpsDirectoryOffset);
    }

    // Cleanup
    TIFFClose(tif);
    free(buffer);

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

        LLVMFuzzerTestOneInput_48(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    