// This fuzz driver is generated for library libtiff, aiming to fuzz the following functions:
// TIFFGetSizeProc at tif_open.c:937:14 in tiffio.h
// TIFFClose at tif_close.c:155:6 in tiffio.h
// TIFFClientOpenExt at tif_open.c:300:7 in tiffio.h
// TIFFGetReadProc at tif_open.c:917:19 in tiffio.h
// TIFFGetSeekProc at tif_open.c:927:14 in tiffio.h
// TIFFGetCloseProc at tif_open.c:932:15 in tiffio.h
// TIFFGetSizeProc at tif_open.c:937:14 in tiffio.h
// TIFFClose at tif_close.c:155:6 in tiffio.h
// TIFFClientOpen at tif_open.c:289:7 in tiffio.h
// TIFFGetReadProc at tif_open.c:917:19 in tiffio.h
// TIFFGetSeekProc at tif_open.c:927:14 in tiffio.h
// TIFFGetCloseProc at tif_open.c:932:15 in tiffio.h
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

static tmsize_t dummyReadProc(thandle_t, void*, tmsize_t) {
    return 0;
}

static tmsize_t dummyWriteProc(thandle_t, void*, tmsize_t) {
    return 0;
}

static toff_t dummySeekProc(thandle_t, toff_t, int) {
    return 0;
}

static int dummyCloseProc(thandle_t) {
    return 0;
}

static toff_t dummySizeProc(thandle_t) {
    return 0;
}

static int dummyMapFileProc(thandle_t, void**, toff_t*) {
    return 0;
}

static void dummyUnmapFileProc(thandle_t, void*, toff_t) {
}

extern "C" int LLVMFuzzerTestOneInput_43(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Prepare a dummy file if needed
    FILE *file = fopen("./dummy_file", "wb");
    if (file) {
        fwrite(Data, 1, Size, file);
        fclose(file);
    }

    // Prepare dummy thandle_t
    thandle_t dummyHandle = nullptr;

    // Test TIFFClientOpenExt
    TIFF *tiffExt = TIFFClientOpenExt(
        "dummy", "r", dummyHandle,
        dummyReadProc, dummyWriteProc,
        dummySeekProc, dummyCloseProc, dummySizeProc,
        dummyMapFileProc, dummyUnmapFileProc,
        nullptr
    );

    if (tiffExt) {
        // Test TIFFGetReadProc
        TIFFReadWriteProc readProc = TIFFGetReadProc(tiffExt);

        // Test TIFFGetSeekProc
        TIFFSeekProc seekProc = TIFFGetSeekProc(tiffExt);

        // Test TIFFGetCloseProc
        TIFFCloseProc closeProc = TIFFGetCloseProc(tiffExt);

        // Test TIFFGetSizeProc
        TIFFSizeProc sizeProc = TIFFGetSizeProc(tiffExt);

        TIFFClose(tiffExt);
    }

    // Test TIFFClientOpen
    TIFF *tiff = TIFFClientOpen(
        "dummy", "r", dummyHandle,
        dummyReadProc, dummyWriteProc,
        dummySeekProc, dummyCloseProc, dummySizeProc,
        dummyMapFileProc, dummyUnmapFileProc
    );

    if (tiff) {
        // Test TIFFGetReadProc
        TIFFReadWriteProc readProc = TIFFGetReadProc(tiff);

        // Test TIFFGetSeekProc
        TIFFSeekProc seekProc = TIFFGetSeekProc(tiff);

        // Test TIFFGetCloseProc
        TIFFCloseProc closeProc = TIFFGetCloseProc(tiff);

        // Test TIFFGetSizeProc
        TIFFSizeProc sizeProc = TIFFGetSizeProc(tiff);

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

        LLVMFuzzerTestOneInput_43(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    