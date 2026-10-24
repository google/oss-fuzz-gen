// This fuzz driver is generated for library libtiff, aiming to fuzz the following functions:
// TIFFRGBAImageGet at tif_getimage.c:589:5 in tiffio.h
// TIFFOpen at tif_unix.c:232:7 in tiffio.h
// TIFFReadRGBAStripExt at tif_getimage.c:3393:5 in tiffio.h
// TIFFClose at tif_close.c:155:6 in tiffio.h
// TIFFOpen at tif_unix.c:232:7 in tiffio.h
// TIFFReadRGBATile at tif_getimage.c:3462:5 in tiffio.h
// TIFFClose at tif_close.c:155:6 in tiffio.h
// TIFFOpen at tif_unix.c:232:7 in tiffio.h
// TIFFReadRGBAStrip at tif_getimage.c:3387:5 in tiffio.h
// TIFFClose at tif_close.c:155:6 in tiffio.h
// TIFFOpen at tif_unix.c:232:7 in tiffio.h
// TIFFClose at tif_close.c:155:6 in tiffio.h
// TIFFOpen at tif_unix.c:232:7 in tiffio.h
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

static void fuzz_TIFFRGBAImageGet(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(TIFFRGBAImage) + sizeof(uint32_t) * 3) return;

    TIFFRGBAImage img;
    memcpy(&img, Data, sizeof(TIFFRGBAImage));
    uint32_t *raster = (uint32_t *)(Data + sizeof(TIFFRGBAImage));
    uint32_t width = *(uint32_t *)(Data + sizeof(TIFFRGBAImage) + sizeof(uint32_t));
    uint32_t height = *(uint32_t *)(Data + sizeof(TIFFRGBAImage) + 2 * sizeof(uint32_t));

    TIFFRGBAImageGet(&img, raster, width, height);
}

static void fuzz_TIFFReadRGBAStripExt(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(uint32_t) * 2 + sizeof(int)) return;

    uint32_t row = *(uint32_t *)(Data);
    uint32_t *raster = (uint32_t *)(Data + sizeof(uint32_t));
    int stop_on_error = *(int *)(Data + sizeof(uint32_t) * 2);

    TIFF *tiff = TIFFOpen("./dummy_file", "r");
    if (tiff) {
        TIFFReadRGBAStripExt(tiff, row, raster, stop_on_error);
        TIFFClose(tiff);
    }
}

static void fuzz_TIFFReadRGBATile(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(uint32_t) * 3) return;

    uint32_t col = *(uint32_t *)(Data);
    uint32_t row = *(uint32_t *)(Data + sizeof(uint32_t));
    uint32_t *raster = (uint32_t *)(Data + 2 * sizeof(uint32_t));

    TIFF *tiff = TIFFOpen("./dummy_file", "r");
    if (tiff) {
        TIFFReadRGBATile(tiff, col, row, raster);
        TIFFClose(tiff);
    }
}

static void fuzz_TIFFReadRGBAStrip(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(uint32_t) * 2) return;

    uint32_t row = *(uint32_t *)(Data);
    uint32_t *raster = (uint32_t *)(Data + sizeof(uint32_t));

    TIFF *tiff = TIFFOpen("./dummy_file", "r");
    if (tiff) {
        TIFFReadRGBAStrip(tiff, row, raster);
        TIFFClose(tiff);
    }
}

static void fuzz_TIFFReadRGBAImage(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(uint32_t) * 3 + sizeof(int)) return;

    uint32_t width = *(uint32_t *)(Data);
    uint32_t height = *(uint32_t *)(Data + sizeof(uint32_t));
    uint32_t *raster = (uint32_t *)(Data + 2 * sizeof(uint32_t));
    int stop_on_error = *(int *)(Data + 3 * sizeof(uint32_t));

    TIFF *tiff = TIFFOpen("./dummy_file", "r");
    if (tiff) {
        TIFFReadRGBAImage(tiff, width, height, raster, stop_on_error);
        TIFFClose(tiff);
    }
}

static void fuzz_TIFFReadRGBAImageOriented(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(uint32_t) * 3 + sizeof(int) * 2) return;

    uint32_t width = *(uint32_t *)(Data);
    uint32_t height = *(uint32_t *)(Data + sizeof(uint32_t));
    uint32_t *raster = (uint32_t *)(Data + 2 * sizeof(uint32_t));
    int orientation = *(int *)(Data + 3 * sizeof(uint32_t));
    int stop_on_error = *(int *)(Data + 3 * sizeof(uint32_t) + sizeof(int));

    TIFF *tiff = TIFFOpen("./dummy_file", "r");
    if (tiff) {
        TIFFReadRGBAImageOriented(tiff, width, height, raster, orientation, stop_on_error);
        TIFFClose(tiff);
    }
}

extern "C" int LLVMFuzzerTestOneInput_112(const uint8_t *Data, size_t Size) {
    FILE *file = fopen("./dummy_file", "wb");
    if (file) {
        fwrite(Data, 1, Size, file);
        fclose(file);
    }

    fuzz_TIFFRGBAImageGet(Data, Size);
    fuzz_TIFFReadRGBAStripExt(Data, Size);
    fuzz_TIFFReadRGBATile(Data, Size);
    fuzz_TIFFReadRGBAStrip(Data, Size);
    fuzz_TIFFReadRGBAImage(Data, Size);
    fuzz_TIFFReadRGBAImageOriented(Data, Size);
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

        LLVMFuzzerTestOneInput_112(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    