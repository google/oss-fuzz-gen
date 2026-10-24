// This fuzz driver is generated for library libtiff, aiming to fuzz the following functions:
// TIFFOpen at tif_unix.c:232:7 in tiffio.h
// TIFFSetField at tif_dir.c:1152:5 in tiffio.h
// TIFFSetField at tif_dir.c:1152:5 in tiffio.h
// TIFFSetField at tif_dir.c:1152:5 in tiffio.h
// TIFFSetField at tif_dir.c:1152:5 in tiffio.h
// TIFFSetField at tif_dir.c:1152:5 in tiffio.h
// TIFFSetField at tif_dir.c:1152:5 in tiffio.h
// TIFFSetField at tif_dir.c:1152:5 in tiffio.h
// TIFFWriteDirectory at tif_dirwrite.c:238:5 in tiffio.h
// TIFFClose at tif_close.c:155:6 in tiffio.h
// TIFFCreateGPSDirectory at tif_dir.c:1752:5 in tiffio.h
// TIFFReadEXIFDirectory at tif_dirread.c:5556:5 in tiffio.h
// TIFFSetSubDirectory at tif_dir.c:2163:5 in tiffio.h
// TIFFLastDirectory at tif_dir.c:2239:5 in tiffio.h
// TIFFReadDirectory at tif_dirread.c:4323:5 in tiffio.h
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
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>

static TIFF* createDummyTIFF(const char* filename) {
    TIFF* tiff = TIFFOpen(filename, "w");
    if (!tiff) {
        return nullptr;
    }
    // Set some dummy fields to create a valid TIFF structure.
    TIFFSetField(tiff, TIFFTAG_IMAGEWIDTH, 1);
    TIFFSetField(tiff, TIFFTAG_IMAGELENGTH, 1);
    TIFFSetField(tiff, TIFFTAG_SAMPLESPERPIXEL, 1);
    TIFFSetField(tiff, TIFFTAG_BITSPERSAMPLE, 8);
    TIFFSetField(tiff, TIFFTAG_ORIENTATION, ORIENTATION_TOPLEFT);
    TIFFSetField(tiff, TIFFTAG_PLANARCONFIG, PLANARCONFIG_CONTIG);
    TIFFSetField(tiff, TIFFTAG_PHOTOMETRIC, PHOTOMETRIC_MINISBLACK);
    TIFFWriteDirectory(tiff);
    return tiff;
}

static void cleanup(TIFF* tiff, const char* filename) {
    if (tiff) {
        TIFFClose(tiff);
    }
    std::remove(filename);
}

extern "C" int LLVMFuzzerTestOneInput_123(const uint8_t *Data, size_t Size) {
    const char* filename = "./dummy_file";
    TIFF* tiff = createDummyTIFF(filename);
    if (!tiff) {
        return 0;
    }

    // Use the data as an offset or other parameters.
    uint64_t offset = 0;
    if (Size >= sizeof(offset)) {
        std::memcpy(&offset, Data, sizeof(offset));
    }

    // Fuzz TIFFCreateGPSDirectory
    if (TIFFCreateGPSDirectory(tiff) == 0) {
        cleanup(tiff, filename);
        return 0;
    }

    // Fuzz TIFFReadEXIFDirectory
    TIFFReadEXIFDirectory(tiff, static_cast<toff_t>(offset));

    // Fuzz TIFFSetSubDirectory
    TIFFSetSubDirectory(tiff, offset);

    // Fuzz TIFFLastDirectory
    TIFFLastDirectory(tiff);

    // Fuzz TIFFReadDirectory
    TIFFReadDirectory(tiff);

    // Fuzz TIFFReadGPSDirectory
    TIFFReadGPSDirectory(tiff, static_cast<toff_t>(offset));

    cleanup(tiff, filename);
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

        LLVMFuzzerTestOneInput_123(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    