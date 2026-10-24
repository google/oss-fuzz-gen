// This fuzz driver is generated for library libtiff, aiming to fuzz the following functions:
// TIFFOpen at tif_unix.c:232:7 in tiffio.h
// TIFFClose at tif_close.c:155:6 in tiffio.h
// TIFFReadEncodedStrip at tif_read.c:543:10 in tiffio.h
// TIFFReadRawTile at tif_read.c:1186:10 in tiffio.h
// TIFFWriteRawStrip at tif_write.c:328:10 in tiffio.h
// TIFFReadRawStrip at tif_read.c:727:10 in tiffio.h
// TIFFWriteEncodedTile at tif_write.c:414:10 in tiffio.h
// TIFFWriteEncodedStrip at tif_write.c:215:10 in tiffio.h
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
#include <cstdlib>
#include <cstring>
#include <tiffio.h>

extern "C" int LLVMFuzzerTestOneInput_35(const uint8_t *Data, size_t Size) {
    if (Size < 1) {
        return 0;
    }

    // Create a dummy file to work with TIFF functions
    FILE *file = fopen("./dummy_file", "wb");
    if (!file) {
        return 0;
    }
    fwrite(Data, 1, Size, file);
    fclose(file);

    TIFF *tif = TIFFOpen("./dummy_file", "r+");
    if (!tif) {
        return 0;
    }

    // Allocate a buffer for reading/writing
    tmsize_t bufferSize = 1024;
    void *buffer = malloc(bufferSize);
    if (!buffer) {
        TIFFClose(tif);
        return 0;
    }

    // Fuzzing TIFFReadEncodedStrip
    uint32_t stripIndex = 0;
    TIFFReadEncodedStrip(tif, stripIndex, buffer, bufferSize);

    // Fuzzing TIFFReadRawTile
    uint32_t tileIndex = 0;
    TIFFReadRawTile(tif, tileIndex, buffer, bufferSize);

    // Fuzzing TIFFWriteRawStrip
    TIFFWriteRawStrip(tif, stripIndex, buffer, bufferSize);

    // Fuzzing TIFFReadRawStrip
    TIFFReadRawStrip(tif, stripIndex, buffer, bufferSize);

    // Fuzzing TIFFWriteEncodedTile
    TIFFWriteEncodedTile(tif, tileIndex, buffer, bufferSize);

    // Fuzzing TIFFWriteEncodedStrip
    TIFFWriteEncodedStrip(tif, stripIndex, buffer, bufferSize);

    free(buffer);
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

        LLVMFuzzerTestOneInput_35(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    