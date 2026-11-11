// This fuzz driver is generated for library libtiff, aiming to fuzz the following functions:
// TIFFOpen at tif_unix.c:232:7 in tiffio.h
// TIFFClose at tif_close.c:155:6 in tiffio.h
// TIFFWriteTile at tif_write.c:387:10 in tiffio.h
// TIFFReadRawTile at tif_read.c:1186:10 in tiffio.h
// TIFFWriteRawTile at tif_write.c:533:10 in tiffio.h
// TIFFReadEncodedTile at tif_read.c:963:10 in tiffio.h
// TIFFReadTile at tif_read.c:950:10 in tiffio.h
// TIFFWriteEncodedTile at tif_write.c:414:10 in tiffio.h
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

static TIFF* openDummyTIFF(const char* filename) {
    TIFF* tif = TIFFOpen(filename, "w+");
    if (!tif) {
        fprintf(stderr, "Could not open dummy TIFF file.\n");
        return nullptr;
    }
    return tif;
}

static void closeDummyTIFF(TIFF* tif) {
    if (tif) {
        TIFFClose(tif);
    }
}

extern "C" int LLVMFuzzerTestOneInput_39(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    const char* dummyFileName = "./dummy_file";
    FILE* file = fopen(dummyFileName, "wb");
    if (!file) return 0;
    fwrite(Data, 1, Size, file);
    fclose(file);

    TIFF* tif = openDummyTIFF(dummyFileName);
    if (!tif) return 0;

    uint32_t tileIndex = 0;
    tmsize_t bufferSize = 256;
    void* buffer = malloc(bufferSize);
    if (!buffer) {
        closeDummyTIFF(tif);
        return 0;
    }

    // Fuzz TIFFWriteTile
    TIFFWriteTile(tif, buffer, 0, 0, 0, 0);

    // Fuzz TIFFReadRawTile
    TIFFReadRawTile(tif, tileIndex, buffer, bufferSize);

    // Fuzz TIFFWriteRawTile
    TIFFWriteRawTile(tif, tileIndex, buffer, bufferSize);

    // Fuzz TIFFReadEncodedTile
    TIFFReadEncodedTile(tif, tileIndex, buffer, bufferSize);

    // Fuzz TIFFReadTile
    TIFFReadTile(tif, buffer, 0, 0, 0, 0);

    // Fuzz TIFFWriteEncodedTile
    TIFFWriteEncodedTile(tif, tileIndex, buffer, bufferSize);

    free(buffer);
    closeDummyTIFF(tif);

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

        LLVMFuzzerTestOneInput_39(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    