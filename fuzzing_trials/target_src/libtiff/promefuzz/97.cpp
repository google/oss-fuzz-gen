// This fuzz driver is generated for library libtiff, aiming to fuzz the following functions:
// TIFFOpen at tif_unix.c:232:7 in tiffio.h
// TIFFOpen at tif_unix.c:232:7 in tiffio.h
// TIFFClose at tif_close.c:155:6 in tiffio.h
// _TIFFmalloc at tif_unix.c:333:7 in tiffio.h
// TIFFYCbCrToRGBInit at tif_color.c:251:5 in tiffio.h
// TIFFReadEncodedStrip at tif_read.c:543:10 in tiffio.h
// TIFFYCbCrtoRGB at tif_color.c:199:6 in tiffio.h
// _TIFFfree at tif_unix.c:349:6 in tiffio.h
// TIFFMergeFieldInfo at tif_dirinfo.c:1238:5 in tiffio.h
// TIFFSetDirectory at tif_dir.c:2067:5 in tiffio.h
// TIFFReadGPSDirectory at tif_dirread.c:5564:5 in tiffio.h
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

static TIFF* initializeTIFF(const char* filename) {
    TIFF* tif = TIFFOpen(filename, "r+");
    if (!tif) {
        tif = TIFFOpen(filename, "w+");
    }
    return tif;
}

static void cleanupTIFF(TIFF* tif) {
    if (tif) {
        TIFFClose(tif);
    }
}

static TIFFYCbCrToRGB* initializeYCbCrToRGB() {
    size_t bufferSize = sizeof(TIFFYCbCrToRGB) +
                        4 * 256 * sizeof(TIFFRGBValue) + 
                        2 * 256 * sizeof(int) + 
                        3 * 256 * sizeof(int32_t);
    TIFFYCbCrToRGB* ycbcr = (TIFFYCbCrToRGB*)_TIFFmalloc(bufferSize);
    if (ycbcr) {
        float luma[3] = {1.0f, 1.0f, 1.0f};
        float refBlackWhite[6] = {0.0f, 255.0f, 128.0f, 128.0f, 128.0f, 128.0f};
        TIFFYCbCrToRGBInit(ycbcr, luma, refBlackWhite);
    }
    return ycbcr;
}

extern "C" int LLVMFuzzerTestOneInput_97(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    FILE* file = fopen("./dummy_file", "wb");
    if (!file) return 0;

    fwrite(Data, 1, Size, file);
    fclose(file);

    TIFF* tif = initializeTIFF("./dummy_file");
    if (!tif) return 0;

    uint32_t strip = 0;
    tmsize_t bufSize = 1024;
    uint8_t* buf = (uint8_t*)malloc(bufSize);
    if (buf) {
        TIFFReadEncodedStrip(tif, strip, buf, bufSize);
        free(buf);
    }

    TIFFYCbCrToRGB* ycbcr = initializeYCbCrToRGB();
    if (ycbcr) {
        uint32_t Y = 128, R, G, B;
        int32_t Cb = 128, Cr = 128;
        TIFFYCbCrtoRGB(ycbcr, Y, Cb, Cr, &R, &G, &B);
        _TIFFfree(ycbcr);
    }

    TIFFFieldInfo fieldInfo;
    TIFFMergeFieldInfo(tif, &fieldInfo, 1);

    buf = (uint8_t*)malloc(bufSize);
    if (buf) {
        TIFFWriteScanline(tif, buf, 0, 0);
        free(buf);
    }

    TIFFSetDirectory(tif, 0);

    TIFFReadGPSDirectory(tif, 0);

    cleanupTIFF(tif);
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

        LLVMFuzzerTestOneInput_97(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    