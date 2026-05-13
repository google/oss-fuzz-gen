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

static TIFF* initializeTIFF(const uint8_t *Data, size_t Size) {
    FILE *file = fopen("./dummy_file", "wb");
    if (!file) {
        return nullptr;
    }

    if (fwrite(Data, 1, Size, file) != Size) {
        fclose(file);
        return nullptr;
    }
    fclose(file);

    TIFF *tif = TIFFOpen("./dummy_file", "r");
    return tif;
}

static void cleanupTIFF(TIFF *tif) {
    if (tif) {
        TIFFClose(tif);
    }
    remove("./dummy_file");
}

extern "C" int LLVMFuzzerTestOneInput_15(const uint8_t *Data, size_t Size) {
    if (Size < 4) {
        return 0; // Not enough data to proceed
    }

    TIFF *tif = initializeTIFF(Data, Size);
    if (!tif) {
        return 0;
    }

    // Example of fuzzing TIFFVStripSize
    uint32_t nrows = *(reinterpret_cast<const uint32_t*>(Data));
    tmsize_t vStripSize = TIFFVStripSize(tif, nrows);

    // Example of fuzzing TIFFRawStripSize
    uint32_t strip = *(reinterpret_cast<const uint32_t*>(Data + 4));
    tmsize_t rawStripSize = TIFFRawStripSize(tif, strip);

    // Example of fuzzing TIFFStripSize
    tmsize_t stripSize = TIFFStripSize(tif);

    // Example of fuzzing TIFFReadEncodedTile
    uint32_t tile = *(reinterpret_cast<const uint32_t*>(Data + 8));
    void *buf = malloc(1024); // Allocate a buffer for reading
    if (buf) {
        tmsize_t readEncodedTileSize = TIFFReadEncodedTile(tif, tile, buf, 1024);
        free(buf);
    }

    // Example of fuzzing TIFFVTileSize
    tmsize_t vTileSize = TIFFVTileSize(tif, nrows);

    // Example of fuzzing TIFFTileRowSize
    tmsize_t tileRowSize = TIFFTileRowSize(tif);

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

    LLVMFuzzerTestOneInput_15(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
