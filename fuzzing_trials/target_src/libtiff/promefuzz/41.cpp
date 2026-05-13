// This fuzz driver is generated for library libtiff, aiming to fuzz the following functions:
// TIFFOpen at tif_unix.c:232:7 in tiffio.h
// TIFFReadRGBAStripExt at tif_getimage.c:3393:5 in tiffio.h
// TIFFReadRGBATile at tif_getimage.c:3462:5 in tiffio.h
// TIFFReadRGBATileExt at tif_getimage.c:3468:5 in tiffio.h
// TIFFReadRGBAStrip at tif_getimage.c:3387:5 in tiffio.h
// TIFFRGBAImageGet at tif_getimage.c:589:5 in tiffio.h
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

static TIFF* createTIFF(const uint8_t *Data, size_t Size) {
    FILE* file = fopen("./dummy_file", "wb");
    if (!file) return nullptr;
    fwrite(Data, 1, Size, file);
    fclose(file);
    return TIFFOpen("./dummy_file", "r");
}

extern "C" int LLVMFuzzerTestOneInput_41(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(uint32_t) * 4) {
        return 0;
    }

    TIFF* tiff = createTIFF(Data, Size);
    if (!tiff) {
        return 0;
    }

    uint32_t row = 0;
    uint32_t col = 0;
    uint32_t raster[256];
    int stop_on_error = 0;

    // Fuzz TIFFReadRGBAStripExt
    TIFFReadRGBAStripExt(tiff, row, raster, stop_on_error);

    // Fuzz TIFFReadRGBATile
    TIFFReadRGBATile(tiff, col, row, raster);

    // Fuzz TIFFReadRGBATileExt
    TIFFReadRGBATileExt(tiff, col, row, raster, stop_on_error);

    // Fuzz TIFFReadRGBAStrip
    TIFFReadRGBAStrip(tiff, row, raster);

    // Fuzz TIFFReadRGBAImage
    TIFFReadRGBAImage(tiff, 256, 256, raster, stop_on_error);

    // Fuzz TIFFRGBAImageGet
    TIFFRGBAImage rgbaImage;
    memset(&rgbaImage, 0, sizeof(TIFFRGBAImage));
    rgbaImage.tif = tiff;
    TIFFRGBAImageGet(&rgbaImage, raster, 256, 256);

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

        LLVMFuzzerTestOneInput_41(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    