// This fuzz driver is generated for library libtiff, aiming to fuzz the following functions:
// TIFFOpen at tif_unix.c:232:7 in tiffio.h
// TIFFSetDirectory at tif_dir.c:2067:5 in tiffio.h
// TIFFSetDirectory at tif_dir.c:2067:5 in tiffio.h
// TIFFCurrentDirOffset at tif_dir.c:2233:10 in tiffio.h
// TIFFGetSeekProc at tif_open.c:927:14 in tiffio.h
// TIFFIsByteSwapped at tif_open.c:889:5 in tiffio.h
// TIFFSwabLong at tif_swab.c:45:6 in tiffio.h
// TIFFGetWriteProc at tif_open.c:922:19 in tiffio.h
// TIFFNumberOfDirectories at tif_dir.c:2042:8 in tiffio.h
// TIFFSetDirectory at tif_dir.c:2067:5 in tiffio.h
// TIFFSetDirectory at tif_dir.c:2067:5 in tiffio.h
// TIFFClose at tif_close.c:155:6 in tiffio.h
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

static void WriteDummyFile(const uint8_t *Data, size_t Size) {
    FILE *file = fopen("./dummy_file", "wb");
    if (file) {
        fwrite(Data, 1, Size, file);
        fclose(file);
    }
}

extern "C" int LLVMFuzzerTestOneInput_5(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0; // Ensure there's at least some data

    // Write data to a dummy file
    WriteDummyFile(Data, Size);

    // Open the TIFF file
    TIFF* tiff = TIFFOpen("./dummy_file", "r");
    if (!tiff) return 0;

    // Attempt to set directories
    TIFFSetDirectory(tiff, 0);
    TIFFSetDirectory(tiff, 1);

    // Get the current directory offset
    TIFFCurrentDirOffset(tiff);

    // Get the seek procedure
    TIFFGetSeekProc(tiff);

    // Check if byte swapping is needed
    TIFFIsByteSwapped(tiff);

    // Swab a long integer (dummy value in this case)
    uint32_t dummyLong = 0x12345678;
    TIFFSwabLong(&dummyLong);

    // Get the write procedure
    TIFFGetWriteProc(tiff);

    // Get the number of directories
    TIFFNumberOfDirectories(tiff);

    // Set directories again
    TIFFSetDirectory(tiff, 2);
    TIFFSetDirectory(tiff, 3);

    // Close the TIFF file twice as per the task specification
    TIFFClose(tiff);
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

        LLVMFuzzerTestOneInput_5(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    