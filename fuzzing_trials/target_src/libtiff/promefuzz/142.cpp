// This fuzz driver is generated for library libtiff, aiming to fuzz the following functions:
// TIFFClientOpen at tif_open.c:289:7 in tiffio.h
// LogL10toY at tif_luv.c:883:5 in tiffio.h
// LogL16toY at tif_luv.c:801:5 in tiffio.h
// TIFFForceStrileArrayWriting at tif_flush.c:76:5 in tiffio.h
// TIFFFlushData at tif_flush.c:146:5 in tiffio.h
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
#include <cmath>
#include <cstring>

static TIFF* createDummyTIFF() {
    FILE* file = fopen("./dummy_file", "w+b");
    if (!file) return nullptr;
    TIFF* tif = TIFFClientOpen("dummy", "w+", file,
                               [](thandle_t fd, void* buf, tmsize_t size) -> tmsize_t {
                                   return fread(buf, 1, size, (FILE*)fd);
                               },
                               [](thandle_t fd, void* buf, tmsize_t size) -> tmsize_t {
                                   return fwrite(buf, 1, size, (FILE*)fd);
                               },
                               [](thandle_t fd, toff_t off, int whence) -> toff_t {
                                   return fseek((FILE*)fd, off, whence);
                               },
                               [](thandle_t fd) -> int {
                                   return fclose((FILE*)fd);
                               },
                               [](thandle_t fd) -> toff_t {
                                   long pos = ftell((FILE*)fd);
                                   fseek((FILE*)fd, 0, SEEK_END);
                                   long end = ftell((FILE*)fd);
                                   fseek((FILE*)fd, pos, SEEK_SET);
                                   return end;
                               },
                               nullptr, nullptr);
    return tif;
}

extern "C" int LLVMFuzzerTestOneInput_142(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(double) + sizeof(int)) {
        return 0;
    }

    double Y = *reinterpret_cast<const double*>(Data);
    int param = *reinterpret_cast<const int*>(Data + sizeof(double));

    // Fuzz LogL10fromY
    if (Y > 0) {
        int resultLogL10fromY = LogL10fromY(Y, param);
    }

    // Fuzz LogL16fromY
    int resultLogL16fromY = LogL16fromY(Y, param);

    // Fuzz LogL10toY
    int intValue = *reinterpret_cast<const int*>(Data);
    double resultLogL10toY = LogL10toY(intValue);

    // Fuzz LogL16toY
    double resultLogL16toY = LogL16toY(intValue);

    // Create a dummy TIFF object
    TIFF* tif = createDummyTIFF();
    if (tif) {
        // Fuzz TIFFForceStrileArrayWriting
        int resultTIFFForceStrileArrayWriting = TIFFForceStrileArrayWriting(tif);

        // Fuzz TIFFFlushData
        int resultTIFFFlushData = TIFFFlushData(tif);

        TIFFClose(tif);
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

        LLVMFuzzerTestOneInput_142(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    