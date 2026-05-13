// This fuzz driver is generated for library libtiff, aiming to fuzz the following functions:
// TIFFOpen at tif_unix.c:232:7 in tiffio.h
// TIFFComputeTile at tif_tile.c:35:10 in tiffio.h
// TIFFComputeStrip at tif_strip.c:35:10 in tiffio.h
// TIFFDefaultTileSize at tif_tile.c:267:6 in tiffio.h
// TIFFTileSize at tif_tile.c:253:10 in tiffio.h
// TIFFReadTile at tif_read.c:950:10 in tiffio.h
// TIFFCurrentTile at tif_open.c:884:10 in tiffio.h
// TIFFNumberOfTiles at tif_tile.c:108:10 in tiffio.h
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

extern "C" int LLVMFuzzerTestOneInput_76(const uint8_t *Data, size_t Size) {
    // Create a dummy TIFF structure for testing
    TIFF *tif = TIFFOpen("./dummy_file", "w+");
    if (!tif) {
        return 0;
    }

    uint32_t x = 0, y = 0, z = 0;
    uint16_t s = 0;
    uint32_t tileWidth = 0, tileHeight = 0;
    tmsize_t tileSize;
    void *buffer = nullptr;

    // TIFFComputeTile
    if (Size >= sizeof(uint32_t) * 3 + sizeof(uint16_t)) {
        memcpy(&x, Data, sizeof(uint32_t));
        memcpy(&y, Data + sizeof(uint32_t), sizeof(uint32_t));
        memcpy(&z, Data + 2 * sizeof(uint32_t), sizeof(uint32_t));
        memcpy(&s, Data + 3 * sizeof(uint32_t), sizeof(uint16_t));
        TIFFComputeTile(tif, x, y, z, s);
    }

    // TIFFComputeStrip
    if (Size >= sizeof(uint32_t) + sizeof(uint16_t)) {
        memcpy(&y, Data, sizeof(uint32_t));
        memcpy(&s, Data + sizeof(uint32_t), sizeof(uint16_t));
        TIFFComputeStrip(tif, y, s);
    }

    // TIFFDefaultTileSize
    TIFFDefaultTileSize(tif, &tileWidth, &tileHeight);

    // Prepare buffer for TIFFReadTile
    tileSize = TIFFTileSize(tif);
    if (tileSize > 0) {
        buffer = malloc(tileSize);
        if (buffer) {
            TIFFReadTile(tif, buffer, x, y, z, s);
        }
    }

    // TIFFCurrentTile
    TIFFCurrentTile(tif);

    // TIFFNumberOfTiles
    TIFFNumberOfTiles(tif);

    // Clean up
    if (buffer) {
        free(buffer);
    }
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

        LLVMFuzzerTestOneInput_76(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    