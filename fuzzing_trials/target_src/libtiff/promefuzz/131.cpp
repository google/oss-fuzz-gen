// This fuzz driver is generated for library libtiff, aiming to fuzz the following functions:
// TIFFClose at tif_close.c:155:6 in tiffio.h
// TIFFOpen at tif_unix.c:232:7 in tiffio.h
// TIFFRGBAImageGet at tif_getimage.c:589:5 in tiffio.h
// TIFFReadRGBAStripExt at tif_getimage.c:3393:5 in tiffio.h
// TIFFReadRGBATile at tif_getimage.c:3462:5 in tiffio.h
// TIFFReadRGBAStrip at tif_getimage.c:3387:5 in tiffio.h
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
#include <cstdlib>
#include <cstdio>
#include <cstring>

static TIFF* initializeTIFF(const uint8_t *Data, size_t Size) {
    FILE *file = fopen("./dummy_file", "wb");
    if (!file) return nullptr;
    fwrite(Data, 1, Size, file);
    fclose(file);
    return TIFFOpen("./dummy_file", "rb");
}

static void fuzzTIFFRGBAImageGet(const uint8_t *Data, size_t Size) {
    TIFFRGBAImage img;
    uint32_t *raster = nullptr;
    uint32_t width = 100, height = 100; // Example dimensions

    if (Size < sizeof(TIFFRGBAImage)) return;
    memcpy(&img, Data, sizeof(TIFFRGBAImage));

    raster = (uint32_t *)malloc(width * height * sizeof(uint32_t));
    if (!raster) return;

    TIFFRGBAImageGet(&img, raster, width, height);

    free(raster);
}

static void fuzzTIFFReadRGBAStripExt(TIFF *tiff, const uint8_t *Data, size_t Size) {
    uint32_t row = 0;
    uint32_t *raster = (uint32_t *)malloc(100 * sizeof(uint32_t)); // Example size
    int stop_on_error = 1;

    if (!raster) return;

    TIFFReadRGBAStripExt(tiff, row, raster, stop_on_error);

    free(raster);
}

static void fuzzTIFFReadRGBATile(TIFF *tiff, const uint8_t *Data, size_t Size) {
    uint32_t col = 0, row = 0;
    uint32_t *raster = (uint32_t *)malloc(100 * sizeof(uint32_t)); // Example size

    if (!raster) return;

    TIFFReadRGBATile(tiff, col, row, raster);

    free(raster);
}

static void fuzzTIFFReadRGBAStrip(TIFF *tiff, const uint8_t *Data, size_t Size) {
    uint32_t row = 0;
    uint32_t *raster = (uint32_t *)malloc(100 * sizeof(uint32_t)); // Example size

    if (!raster) return;

    TIFFReadRGBAStrip(tiff, row, raster);

    free(raster);
}

static void fuzzTIFFReadRGBAImage(TIFF *tiff, const uint8_t *Data, size_t Size) {
    uint32_t width = 100, height = 100;
    uint32_t *raster = (uint32_t *)malloc(width * height * sizeof(uint32_t));
    int stop_on_error = 1;

    if (!raster) return;

    TIFFReadRGBAImage(tiff, width, height, raster, stop_on_error);

    free(raster);
}

static void fuzzTIFFReadRGBAImageOriented(TIFF *tiff, const uint8_t *Data, size_t Size) {
    uint32_t width = 100, height = 100;
    uint32_t *raster = (uint32_t *)malloc(width * height * sizeof(uint32_t));
    int orientation = ORIENTATION_TOPLEFT;
    int stop_on_error = 1;

    if (!raster) return;

    TIFFReadRGBAImageOriented(tiff, width, height, raster, orientation, stop_on_error);

    free(raster);
}

extern "C" int LLVMFuzzerTestOneInput_131(const uint8_t *Data, size_t Size) {
    TIFF *tiff = initializeTIFF(Data, Size);
    if (!tiff) return 0;

    fuzzTIFFRGBAImageGet(Data, Size);
    fuzzTIFFReadRGBAStripExt(tiff, Data, Size);
    fuzzTIFFReadRGBATile(tiff, Data, Size);
    fuzzTIFFReadRGBAStrip(tiff, Data, Size);
    fuzzTIFFReadRGBAImage(tiff, Data, Size);
    fuzzTIFFReadRGBAImageOriented(tiff, Data, Size);

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

        LLVMFuzzerTestOneInput_131(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    