// This fuzz driver is generated for library libtiff, aiming to fuzz the following functions:
// TIFFOpen at tif_unix.c:232:7 in tiffio.h
// TIFFIsBigTIFF at tif_open.c:912:5 in tiffio.h
// TIFFReadEXIFDirectory at tif_dirread.c:5556:5 in tiffio.h
// TIFFReadCustomDirectory at tif_dirread.c:5372:5 in tiffio.h
// TIFFGetMapFileProc at tif_open.c:942:17 in tiffio.h
// TIFFReadDirectory at tif_dirread.c:4323:5 in tiffio.h
// TIFFFreeDirectory at tif_dir.c:1629:6 in tiffio.h
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

extern "C" int LLVMFuzzerTestOneInput_63(const uint8_t *Data, size_t Size) {
    // Prepare a dummy file
    FILE *file = fopen("./dummy_file", "wb");
    if (!file) {
        return 0;
    }
    fwrite(Data, 1, Size, file);
    fclose(file);

    // Open the dummy file with TIFFOpen
    TIFF *tiffFile = TIFFOpen("./dummy_file", "r");
    if (!tiffFile) {
        return 0;
    }

    // Invoke TIFFIsBigTIFF
    int isBigTIFF = TIFFIsBigTIFF(tiffFile);

    // Invoke TIFFReadEXIFDirectory with an arbitrary offset
    toff_t exifOffset = 0;
    if (Size >= sizeof(toff_t)) {
        memcpy(&exifOffset, Data, sizeof(toff_t));
    }
    int exifStatus = TIFFReadEXIFDirectory(tiffFile, exifOffset);

    // Invoke TIFFReadCustomDirectory with an arbitrary offset and a dummy infoarray
    const TIFFFieldArray *infoArray = nullptr; // Use nullptr as we don't have a real info array
    int customDirStatus = TIFFReadCustomDirectory(tiffFile, exifOffset, infoArray);

    // Invoke TIFFGetMapFileProc
    TIFFMapFileProc mapFileProc = TIFFGetMapFileProc(tiffFile);

    // Invoke TIFFReadDirectory
    int readDirStatus = TIFFReadDirectory(tiffFile);

    // Clean up
    TIFFFreeDirectory(tiffFile);
    TIFFClose(tiffFile);

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

        LLVMFuzzerTestOneInput_63(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    