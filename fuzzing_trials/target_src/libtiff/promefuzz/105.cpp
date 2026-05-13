// This fuzz driver is generated for library libtiff, aiming to fuzz the following functions:
// TIFFOpen at tif_unix.c:232:7 in tiffio.h
// TIFFNumberOfDirectories at tif_dir.c:2042:8 in tiffio.h
// TIFFComputeStrip at tif_strip.c:35:10 in tiffio.h
// TIFFCurrentStrip at tif_open.c:879:10 in tiffio.h
// TIFFCurrentTile at tif_open.c:884:10 in tiffio.h
// TIFFCurrentDirectory at tif_open.c:874:8 in tiffio.h
// TIFFCurrentRow at tif_open.c:869:10 in tiffio.h
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

extern "C" int LLVMFuzzerTestOneInput_105(const uint8_t *Data, size_t Size) {
    // Create a dummy TIFF file
    FILE *file = fopen("./dummy_file", "wb");
    if (!file) return 0;
    fwrite(Data, 1, Size, file);
    fclose(file);

    // Open the dummy TIFF file
    TIFF *tif = TIFFOpen("./dummy_file", "r");
    if (!tif) return 0;

    // Fuzz TIFFNumberOfDirectories
    tdir_t numDirs = TIFFNumberOfDirectories(tif);

    // Fuzz TIFFComputeStrip
    uint32_t strip = TIFFComputeStrip(tif, 0, 0);

    // Fuzz TIFFCurrentStrip
    uint32_t currentStrip = TIFFCurrentStrip(tif);

    // Fuzz TIFFCurrentTile
    uint32_t currentTile = TIFFCurrentTile(tif);

    // Fuzz TIFFCurrentDirectory
    tdir_t currentDir = TIFFCurrentDirectory(tif);

    // Fuzz TIFFCurrentRow
    uint32_t currentRow = TIFFCurrentRow(tif);

    // Cleanup
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

        LLVMFuzzerTestOneInput_105(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    