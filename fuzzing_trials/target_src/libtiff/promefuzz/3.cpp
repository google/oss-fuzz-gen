// This fuzz driver is generated for library libtiff, aiming to fuzz the following functions:
// TIFFOpen at tif_unix.c:232:7 in tiffio.h
// TIFFFileName at tif_open.c:803:13 in tiffio.h
// TIFFFieldWithTag at tif_dirinfo.c:930:18 in tiffio.h
// TIFFFieldWithTag at tif_dirinfo.c:930:18 in tiffio.h
// TIFFFieldWithTag at tif_dirinfo.c:930:18 in tiffio.h
// TIFFFieldWithTag at tif_dirinfo.c:930:18 in tiffio.h
// TIFFTileSize at tif_tile.c:253:10 in tiffio.h
// TIFFFieldWithTag at tif_dirinfo.c:930:18 in tiffio.h
// _TIFFmalloc at tif_unix.c:333:7 in tiffio.h
// TIFFClose at tif_close.c:155:6 in tiffio.h
// TIFFNumberOfTiles at tif_tile.c:108:10 in tiffio.h
// TIFFWriteEncodedTile at tif_write.c:414:10 in tiffio.h
// _TIFFfree at tif_unix.c:349:6 in tiffio.h
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

extern "C" int LLVMFuzzerTestOneInput_3(const uint8_t *Data, size_t Size) {
    // Step 1: Prepare a dummy TIFF file
    const char *dummyFileName = "./dummy_file.tiff";
    FILE *dummyFile = fopen(dummyFileName, "wb");
    if (!dummyFile) {
        return 0;
    }
    fwrite(Data, 1, Size, dummyFile);
    fclose(dummyFile);

    // Step 2: Open the TIFF file
    TIFF *tif = TIFFOpen(dummyFileName, "r+");
    if (!tif) {
        return 0;
    }

    // Step 3: Invoke TIFFFileName
    const char *fileName = TIFFFileName(tif);

    // Step 4: Invoke TIFFFieldWithTag multiple times
    TIFFFieldWithTag(tif, 256); // Width
    TIFFFieldWithTag(tif, 257); // Height
    TIFFFieldWithTag(tif, 258); // BitsPerSample
    TIFFFieldWithTag(tif, 259); // Compression

    // Step 5: Invoke TIFFTileSize
    tmsize_t tileSize = TIFFTileSize(tif);

    // Step 6: Invoke TIFFFieldWithTag again
    TIFFFieldWithTag(tif, 262); // Photometric

    // Step 7: Invoke _TIFFmalloc
    void *buffer = _TIFFmalloc(tileSize);
    if (!buffer) {
        TIFFClose(tif);
        return 0;
    }

    // Step 8: Invoke TIFFNumberOfTiles
    uint32_t numTiles = TIFFNumberOfTiles(tif);

    // Step 9: Invoke TIFFWriteEncodedTile
    if (numTiles > 0) {
        TIFFWriteEncodedTile(tif, 0, buffer, tileSize);
    }

    // Step 10: Invoke TIFFWriteScanline twice
    TIFFWriteScanline(tif, buffer, 0, 0);
    TIFFWriteScanline(tif, buffer, 1, 0);

    // Step 11: Cleanup
    _TIFFfree(buffer);
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

        LLVMFuzzerTestOneInput_3(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    