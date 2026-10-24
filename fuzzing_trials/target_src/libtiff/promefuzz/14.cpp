// This fuzz driver is generated for library libtiff, aiming to fuzz the following functions:
// TIFFOpen at tif_unix.c:232:7 in tiffio.h
// TIFFGetField at tif_dir.c:1592:5 in tiffio.h
// TIFFTileSize at tif_tile.c:253:10 in tiffio.h
// _TIFFmalloc at tif_unix.c:333:7 in tiffio.h
// TIFFReadEncodedTile at tif_read.c:963:10 in tiffio.h
// _TIFFfree at tif_unix.c:349:6 in tiffio.h
// TIFFSetField at tif_dir.c:1152:5 in tiffio.h
// TIFFTileSize at tif_tile.c:253:10 in tiffio.h
// _TIFFmalloc at tif_unix.c:333:7 in tiffio.h
// TIFFReadEncodedTile at tif_read.c:963:10 in tiffio.h
// _TIFFfree at tif_unix.c:349:6 in tiffio.h
// TIFFClose at tif_close.c:155:6 in tiffio.h
// TIFFOpen at tif_unix.c:232:7 in tiffio.h
// _TIFFmalloc at tif_unix.c:333:7 in tiffio.h
// TIFFReadRGBATile at tif_getimage.c:3462:5 in tiffio.h
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
#include <cstring>

static void WriteDummyFile(const uint8_t *Data, size_t Size) {
    FILE *file = fopen("./dummy_file", "wb");
    if (file) {
        fwrite(Data, 1, Size, file);
        fclose(file);
    }
}

extern "C" int LLVMFuzzerTestOneInput_14(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Write the input data to a dummy file
    WriteDummyFile(Data, Size);

    // Open the dummy file with TIFFOpen
    TIFF *tiff = TIFFOpen("./dummy_file", "r");
    if (!tiff) return 0;

    // Try to get a field
    uint32_t tag = 0;
    TIFFGetField(tiff, tag, nullptr);

    // Get the tile size
    tmsize_t tileSize = TIFFTileSize(tiff);

    // Prepare a buffer for reading encoded tile
    if (tileSize > 0) {
        void *buf = _TIFFmalloc(tileSize);
        if (buf) {
            TIFFReadEncodedTile(tiff, 0, buf, tileSize);
            _TIFFfree(buf);
        }
    }

    // Set a field
    TIFFSetField(tiff, tag, 0);

    // Get the tile size again
    tileSize = TIFFTileSize(tiff);

    // Prepare a buffer for reading encoded tile again
    if (tileSize > 0) {
        void *buf = _TIFFmalloc(tileSize);
        if (buf) {
            TIFFReadEncodedTile(tiff, 0, buf, tileSize);
            _TIFFfree(buf);
        }
    }

    // Close the TIFF file
    TIFFClose(tiff);

    // Reopen the TIFF file
    tiff = TIFFOpen("./dummy_file", "r");
    if (tiff) {
        // Prepare a buffer for reading RGB tile
        uint32_t *raster = (uint32_t *)_TIFFmalloc(tileSize * sizeof(uint32_t));
        if (raster) {
            TIFFReadRGBATile(tiff, 0, 0, raster);
            _TIFFfree(raster);
        }

        // Close the TIFF file
        TIFFClose(tiff);
    }

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

        LLVMFuzzerTestOneInput_14(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    