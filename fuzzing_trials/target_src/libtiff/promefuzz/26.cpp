// This fuzz driver is generated for library libtiff, aiming to fuzz the following functions:
// TIFFOpen at tif_unix.c:232:7 in tiffio.h
// TIFFForceStrileArrayWriting at tif_flush.c:76:5 in tiffio.h
// TIFFIsMSB2LSB at tif_open.c:899:5 in tiffio.h
// TIFFSetupStrips at tif_write.c:553:5 in tiffio.h
// TIFFFileno at tif_open.c:818:5 in tiffio.h
// TIFFGetMode at tif_open.c:848:5 in tiffio.h
// TIFFIsTiled at tif_open.c:864:5 in tiffio.h
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

extern "C" int LLVMFuzzerTestOneInput_26(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Create a dummy file to be used by libtiff
    const char *filename = "./dummy_file";
    FILE *file = fopen(filename, "wb");
    if (!file) return 0;
    fwrite(Data, 1, Size, file);
    fclose(file);

    // Open the TIFF file
    TIFF *tif = TIFFOpen(filename, "r+");
    if (!tif) {
        remove(filename);
        return 0;
    }

    // Fuzz TIFFForceStrileArrayWriting
    TIFFForceStrileArrayWriting(tif);

    // Fuzz TIFFIsMSB2LSB
    TIFFIsMSB2LSB(tif);

    // Fuzz TIFFSetupStrips
    TIFFSetupStrips(tif);

    // Fuzz TIFFFileno
    TIFFFileno(tif);

    // Fuzz TIFFGetMode
    TIFFGetMode(tif);

    // Fuzz TIFFIsTiled
    TIFFIsTiled(tif);

    // Clean up
    TIFFClose(tif);
    remove(filename);

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

        LLVMFuzzerTestOneInput_26(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    