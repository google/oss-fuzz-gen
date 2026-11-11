// This fuzz driver is generated for library libtiff, aiming to fuzz the following functions:
// TIFFSetErrorHandler at tif_error.c:32:18 in tiffio.h
// TIFFSetWarningHandler at tif_warning.c:32:18 in tiffio.h
// TIFFOpen at tif_unix.c:232:7 in tiffio.h
// TIFFGetField at tif_dir.c:1592:5 in tiffio.h
// TIFFGetField at tif_dir.c:1592:5 in tiffio.h
// _TIFFmalloc at tif_unix.c:333:7 in tiffio.h
// TIFFClose at tif_close.c:155:6 in tiffio.h
// TIFFRGBAImageBegin at tif_getimage.c:310:5 in tiffio.h
// TIFFRGBAImageGet at tif_getimage.c:589:5 in tiffio.h
// TIFFRGBAImageEnd at tif_getimage.c:253:6 in tiffio.h
// TIFFReadRGBAStripExt at tif_getimage.c:3393:5 in tiffio.h
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

static void handleError(const char* module, const char* fmt, va_list ap) {
    // Suppress error messages during fuzzing
}

extern "C" int LLVMFuzzerTestOneInput_96(const uint8_t *Data, size_t Size) {
    if (Size < 4) {
        return 0; // Not enough data to proceed
    }

    // Set up TIFF error handlers to suppress output
    TIFFSetErrorHandler(handleError);
    TIFFSetWarningHandler(handleError);

    // Write the input data to a dummy file
    FILE *file = fopen("./dummy_file", "wb");
    if (!file) {
        return 0;
    }
    fwrite(Data, 1, Size, file);
    fclose(file);

    // Open the dummy file with libtiff
    TIFF *tif = TIFFOpen("./dummy_file", "r");
    if (!tif) {
        return 0;
    }

    // Prepare buffers and variables for function calls
    uint32_t width = 0, height = 0;
    TIFFGetField(tif, TIFFTAG_IMAGEWIDTH, &width);
    TIFFGetField(tif, TIFFTAG_IMAGELENGTH, &height);
    uint32_t *raster = (uint32_t *)_TIFFmalloc(width * height * sizeof(uint32_t));
    if (!raster) {
        TIFFClose(tif);
        return 0;
    }

    // Fuzz TIFFRGBAImageGet
    TIFFRGBAImage img;
    if (TIFFRGBAImageBegin(&img, tif, 0, nullptr)) {
        TIFFRGBAImageGet(&img, raster, width, height);
        TIFFRGBAImageEnd(&img);
    }

    // Fuzz TIFFReadRGBAStripExt
    TIFFReadRGBAStripExt(tif, 0, raster, 1);

    // Fuzz TIFFReadRGBATile
    TIFFReadRGBATile(tif, 0, 0, raster);

    // Fuzz TIFFReadRGBAStrip
    TIFFReadRGBAStrip(tif, 0, raster);

    // Fuzz TIFFReadRGBAImage
    TIFFReadRGBAImage(tif, width, height, raster, 1);

    // Fuzz TIFFReadRGBAImageOriented
    TIFFReadRGBAImageOriented(tif, width, height, raster, ORIENTATION_TOPLEFT, 1);

    // Clean up
    _TIFFfree(raster);
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

        LLVMFuzzerTestOneInput_96(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    