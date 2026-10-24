// This fuzz driver is generated for library libtiff, aiming to fuzz the following functions:
// TIFFOpen at tif_unix.c:232:7 in tiffio.h
// TIFFSetDirectory at tif_dir.c:2067:5 in tiffio.h
// TIFFSetField at tif_dir.c:1152:5 in tiffio.h
// TIFFWriteDirectory at tif_dirwrite.c:238:5 in tiffio.h
// TIFFCreateEXIFDirectory at tif_dir.c:1742:5 in tiffio.h
// TIFFWriteCustomDirectory at tif_dirwrite.c:303:5 in tiffio.h
// TIFFSetField at tif_dir.c:1152:5 in tiffio.h
// TIFFSetField at tif_dir.c:1152:5 in tiffio.h
// TIFFSetField at tif_dir.c:1152:5 in tiffio.h
// TIFFSetField at tif_dir.c:1152:5 in tiffio.h
// TIFFSetField at tif_dir.c:1152:5 in tiffio.h
// TIFFSetField at tif_dir.c:1152:5 in tiffio.h
// TIFFWriteDirectory at tif_dirwrite.c:238:5 in tiffio.h
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
#include <cstdarg>

static void writeDummyFile(const uint8_t *Data, size_t Size) {
    FILE *file = fopen("./dummy_file", "wb");
    if (file) {
        fwrite(Data, 1, Size, file);
        fclose(file);
    }
}

extern "C" int LLVMFuzzerTestOneInput_20(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0; // Ensure there's at least some data

    writeDummyFile(Data, Size);

    TIFF* tif = TIFFOpen("./dummy_file", "r+");
    if (!tif) return 0;

    tdir_t dirNum = static_cast<tdir_t>(Data[0] % 256); // Use first byte for directory number
    if (TIFFSetDirectory(tif, dirNum)) {
        uint32_t tag = TIFFTAG_IMAGEWIDTH; // Example tag
        if (TIFFSetField(tif, tag, 256)) { // Example value
            if (TIFFWriteDirectory(tif)) {
                if (TIFFCreateEXIFDirectory(tif)) {
                    uint64_t offset;
                    if (TIFFWriteCustomDirectory(tif, &offset)) {
                        // Setting multiple fields with example tags and values
                        if (TIFFSetField(tif, TIFFTAG_IMAGELENGTH, 256) &&
                            TIFFSetField(tif, TIFFTAG_BITSPERSAMPLE, 8) &&
                            TIFFSetField(tif, TIFFTAG_COMPRESSION, COMPRESSION_NONE) &&
                            TIFFSetField(tif, TIFFTAG_PHOTOMETRIC, PHOTOMETRIC_RGB) &&
                            TIFFSetField(tif, TIFFTAG_SAMPLESPERPIXEL, 3) &&
                            TIFFSetField(tif, TIFFTAG_PLANARCONFIG, PLANARCONFIG_CONTIG)) {
                            TIFFWriteDirectory(tif);
                        }
                    }
                }
            }
        }
    }

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

        LLVMFuzzerTestOneInput_20(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    