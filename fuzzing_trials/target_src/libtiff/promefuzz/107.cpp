// This fuzz driver is generated for library libtiff, aiming to fuzz the following functions:
// TIFFOpen at tif_unix.c:232:7 in tiffio.h
// TIFFYCbCrtoRGB at tif_color.c:199:6 in tiffio.h
// TIFFMergeFieldInfo at tif_dirinfo.c:1238:5 in tiffio.h
// TIFFClose at tif_close.c:155:6 in tiffio.h
// TIFFCreateEXIFDirectory at tif_dir.c:1742:5 in tiffio.h
// TIFFClose at tif_close.c:155:6 in tiffio.h
// TIFFWriteCustomDirectory at tif_dirwrite.c:303:5 in tiffio.h
// TIFFClose at tif_close.c:155:6 in tiffio.h
// TIFFWriteCheck at tif_write.c:605:5 in tiffio.h
// TIFFClose at tif_close.c:155:6 in tiffio.h
// TIFFCreateDirectory at tif_dir.c:1699:5 in tiffio.h
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
#include <cstdlib>
#include <cstdio>
#include <cstring>

static TIFF *createDummyTIFF() {
    FILE *file = fopen("./dummy_file", "wb+");
    if (!file) return nullptr;
    fclose(file);
    return TIFFOpen("./dummy_file", "w+");
}

extern "C" int LLVMFuzzerTestOneInput_107(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Fuzz TIFFYCbCrtoRGB
    if (Size >= sizeof(TIFFYCbCrToRGB) + 3 * sizeof(int32_t)) {
        TIFFYCbCrToRGB *ycbcr = static_cast<TIFFYCbCrToRGB *>(malloc(sizeof(TIFFYCbCrToRGB) + 4 * 256 * sizeof(TIFFRGBValue) + 2 * 256 * sizeof(int) + 3 * 256 * sizeof(int32_t)));
        if (ycbcr) {
            uint32_t R, G, B;
            TIFFYCbCrtoRGB(ycbcr, Data[0], Data[1], Data[2], &R, &G, &B);
            free(ycbcr);
        }
    }

    // Fuzz TIFFMergeFieldInfo
    TIFF *tiff = createDummyTIFF();
    if (tiff) {
        TIFFFieldInfo fieldInfo;
        if (Size >= sizeof(TIFFFieldInfo)) {
            memcpy(&fieldInfo, Data, sizeof(TIFFFieldInfo));
            TIFFMergeFieldInfo(tiff, &fieldInfo, 1);
        }
        TIFFClose(tiff);
    }

    // Fuzz TIFFCreateEXIFDirectory
    tiff = createDummyTIFF();
    if (tiff) {
        TIFFCreateEXIFDirectory(tiff);
        TIFFClose(tiff);
    }

    // Fuzz TIFFWriteCustomDirectory
    tiff = createDummyTIFF();
    if (tiff) {
        uint64_t offset;
        TIFFWriteCustomDirectory(tiff, &offset);
        TIFFClose(tiff);
    }

    // Fuzz TIFFWriteCheck
    tiff = createDummyTIFF();
    if (tiff) {
        TIFFWriteCheck(tiff, 1, "dummy");
        TIFFClose(tiff);
    }

    // Fuzz TIFFCreateDirectory
    tiff = createDummyTIFF();
    if (tiff) {
        TIFFCreateDirectory(tiff);
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

        LLVMFuzzerTestOneInput_107(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    