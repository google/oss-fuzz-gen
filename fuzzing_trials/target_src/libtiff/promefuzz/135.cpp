// This fuzz driver is generated for library libtiff, aiming to fuzz the following functions:
// _TIFFmalloc at tif_unix.c:333:7 in tiffio.h
// TIFFOpen at tif_unix.c:232:7 in tiffio.h
// _TIFFfree at tif_unix.c:349:6 in tiffio.h
// TIFFRGBAImageGet at tif_getimage.c:589:5 in tiffio.h
// TIFFReadRGBAStripExt at tif_getimage.c:3393:5 in tiffio.h
// TIFFReadRGBATile at tif_getimage.c:3462:5 in tiffio.h
// TIFFReadRGBAStrip at tif_getimage.c:3387:5 in tiffio.h
// TIFFClose at tif_close.c:155:6 in tiffio.h
// _TIFFfree at tif_unix.c:349:6 in tiffio.h
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
#include <cstring>
#include <cstdio>

extern "C" int LLVMFuzzerTestOneInput_135(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(TIFFRGBAImage) + sizeof(uint32_t) * 2) {
        return 0;
    }

    TIFFRGBAImage rgbaImage;
    std::memcpy(&rgbaImage, Data, sizeof(TIFFRGBAImage));
    
    uint32_t width = *reinterpret_cast<const uint32_t*>(Data + sizeof(TIFFRGBAImage));
    uint32_t height = *reinterpret_cast<const uint32_t*>(Data + sizeof(TIFFRGBAImage) + sizeof(uint32_t));
    
    uint32_t *raster = static_cast<uint32_t*>(_TIFFmalloc(width * height * sizeof(uint32_t)));
    if (!raster) {
        return 0;
    }

    TIFF *tif = TIFFOpen("./dummy_file", "r");
    if (!tif) {
        _TIFFfree(raster);
        return 0;
    }

    // Fuzzing TIFFRGBAImageGet
    TIFFRGBAImageGet(&rgbaImage, raster, width, height);

    // Fuzzing TIFFReadRGBAStripExt
    TIFFReadRGBAStripExt(tif, 0, raster, 1);

    // Fuzzing TIFFReadRGBATile
    TIFFReadRGBATile(tif, 0, 0, raster);

    // Fuzzing TIFFReadRGBAStrip
    TIFFReadRGBAStrip(tif, 0, raster);

    // Fuzzing TIFFReadRGBAImage
    TIFFReadRGBAImage(tif, width, height, raster, 1);

    // Fuzzing TIFFReadRGBAImageOriented
    TIFFReadRGBAImageOriented(tif, width, height, raster, 1, 0);

    TIFFClose(tif);
    _TIFFfree(raster);
    
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

        LLVMFuzzerTestOneInput_135(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    