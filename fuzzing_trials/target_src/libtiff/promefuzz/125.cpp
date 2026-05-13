// This fuzz driver is generated for library libtiff, aiming to fuzz the following functions:
// TIFFOpen at tif_unix.c:232:7 in tiffio.h
// TIFFCreateGPSDirectory at tif_dir.c:1752:5 in tiffio.h
// TIFFReadEXIFDirectory at tif_dirread.c:5556:5 in tiffio.h
// TIFFSetSubDirectory at tif_dir.c:2163:5 in tiffio.h
// TIFFLastDirectory at tif_dir.c:2239:5 in tiffio.h
// TIFFReadDirectory at tif_dirread.c:4323:5 in tiffio.h
// TIFFReadGPSDirectory at tif_dirread.c:5564:5 in tiffio.h
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

static TIFF* openDummyTiff(const char* filename) {
    FILE* file = fopen(filename, "wb+");
    if (!file) return nullptr;
    fclose(file);
    return TIFFOpen(filename, "r+");
}

extern "C" int LLVMFuzzerTestOneInput_125(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    const char* dummyFilename = "./dummy_file";
    TIFF* tif = openDummyTiff(dummyFilename);
    if (!tif) return 0;

    // Use some data from the input buffer
    toff_t dirOffset = 0;
    if (Size >= sizeof(toff_t)) {
        memcpy(&dirOffset, Data, sizeof(toff_t));
    }

    uint64_t subDirOffset = 0;
    if (Size >= sizeof(uint64_t)) {
        memcpy(&subDirOffset, Data, sizeof(uint64_t));
    }

    // Call the target API functions
    TIFFCreateGPSDirectory(tif);
    TIFFReadEXIFDirectory(tif, dirOffset);
    TIFFSetSubDirectory(tif, subDirOffset);
    TIFFLastDirectory(tif);
    TIFFReadDirectory(tif);
    TIFFReadGPSDirectory(tif, dirOffset);

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

        LLVMFuzzerTestOneInput_125(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    