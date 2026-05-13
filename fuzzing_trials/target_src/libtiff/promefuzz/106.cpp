// This fuzz driver is generated for library libtiff, aiming to fuzz the following functions:
// TIFFOpen at tif_unix.c:232:7 in tiffio.h
// _TIFFmalloc at tif_unix.c:333:7 in tiffio.h
// TIFFScanlineSize at tif_strip.c:343:10 in tiffio.h
// TIFFNumberOfStrips at tif_strip.c:65:10 in tiffio.h
// TIFFClose at tif_close.c:155:6 in tiffio.h
// TIFFGetField at tif_dir.c:1592:5 in tiffio.h
// TIFFGetField at tif_dir.c:1592:5 in tiffio.h
// TIFFRGBAImageBegin at tif_getimage.c:310:5 in tiffio.h
// TIFFRGBAImageGet at tif_getimage.c:589:5 in tiffio.h
// TIFFRGBAImageEnd at tif_getimage.c:253:6 in tiffio.h
// TIFFReadRGBAStripExt at tif_getimage.c:3393:5 in tiffio.h
// TIFFIsTiled at tif_open.c:864:5 in tiffio.h
// TIFFGetField at tif_dir.c:1592:5 in tiffio.h
// TIFFGetField at tif_dir.c:1592:5 in tiffio.h
// TIFFReadRGBATile at tif_getimage.c:3462:5 in tiffio.h
// TIFFReadRGBAStrip at tif_getimage.c:3387:5 in tiffio.h
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

static void writeDummyFile(const uint8_t *Data, size_t Size) {
    FILE *file = fopen("./dummy_file", "wb");
    if (file) {
        fwrite(Data, 1, Size, file);
        fclose(file);
    }
}

extern "C" int LLVMFuzzerTestOneInput_106(const uint8_t *Data, size_t Size) {
    if (Size < 4) return 0; // Ensure there's enough data for meaningful operations

    writeDummyFile(Data, Size);

    TIFF *tiff = TIFFOpen("./dummy_file", "r");
    if (!tiff) return 0;

    // Prepare buffers and variables for the API functions
    uint32_t *raster = (uint32_t *)_TIFFmalloc(TIFFScanlineSize(tiff) * TIFFNumberOfStrips(tiff));
    if (!raster) {
        TIFFClose(tiff);
        return 0;
    }

    uint32_t width = 0, height = 0;
    TIFFGetField(tiff, TIFFTAG_IMAGEWIDTH, &width);
    TIFFGetField(tiff, TIFFTAG_IMAGELENGTH, &height);

    TIFFRGBAImage img;
    if (TIFFRGBAImageBegin(&img, tiff, 0, nullptr)) {
        // Fuzz TIFFRGBAImageGet
        TIFFRGBAImageGet(&img, raster, width, height);
        TIFFRGBAImageEnd(&img);
    }

    // Fuzz TIFFReadRGBAStripExt
    for (uint32_t row = 0; row < height; row += height) {
        TIFFReadRGBAStripExt(tiff, row, raster, 1);
    }

    // Fuzz TIFFReadRGBATile
    if (TIFFIsTiled(tiff)) {
        uint32_t tileWidth = 0, tileHeight = 0;
        TIFFGetField(tiff, TIFFTAG_TILEWIDTH, &tileWidth);
        TIFFGetField(tiff, TIFFTAG_TILELENGTH, &tileHeight);

        for (uint32_t col = 0; col < width; col += tileWidth) {
            for (uint32_t row = 0; row < height; row += tileHeight) {
                TIFFReadRGBATile(tiff, col, row, raster);
            }
        }
    }

    // Fuzz TIFFReadRGBAStrip
    for (uint32_t row = 0; row < height; row += height) {
        TIFFReadRGBAStrip(tiff, row, raster);
    }

    // Fuzz TIFFReadRGBAImage
    TIFFReadRGBAImage(tiff, width, height, raster, 0);

    // Fuzz TIFFReadRGBAImageOriented
    for (int orientation = 0; orientation < 8; ++orientation) {
        TIFFReadRGBAImageOriented(tiff, width, height, raster, 0, orientation);
    }

    _TIFFfree(raster);
    TIFFClose(tiff);

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

        LLVMFuzzerTestOneInput_106(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    