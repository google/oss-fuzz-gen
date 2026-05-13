// This fuzz driver is generated for library libtiff, aiming to fuzz the following functions:
// TIFFOpen at tif_unix.c:232:7 in tiffio.h
// TIFFClose at tif_close.c:155:6 in tiffio.h
// TIFFDeferStrileArrayWriting at tif_dirwrite.c:268:5 in tiffio.h
// TIFFForceStrileArrayWriting at tif_flush.c:76:5 in tiffio.h
// TIFFIsCODECConfigured at tif_codec.c:146:5 in tiffio.h
// TIFFWriteCheck at tif_write.c:605:5 in tiffio.h
// TIFFIsTiled at tif_open.c:864:5 in tiffio.h
// TIFFWriteDirectory at tif_dirwrite.c:238:5 in tiffio.h
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

static TIFF* createTIFF(const char* filename, const char* mode) {
    return TIFFOpen(filename, mode);
}

static void closeTIFF(TIFF* tiff) {
    if (tiff) {
        TIFFClose(tiff);
    }
}

extern "C" int LLVMFuzzerTestOneInput_46(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(uint16_t)) {
        return 0;
    }

    // Prepare a dummy file
    const char* dummyFileName = "./dummy_file";
    FILE* dummyFile = fopen(dummyFileName, "wb");
    if (!dummyFile) {
        return 0;
    }
    fwrite(Data, 1, Size, dummyFile);
    fclose(dummyFile);

    TIFF* tiff = createTIFF(dummyFileName, "w");
    if (!tiff) {
        return 0;
    }

    // Fuzz TIFFDeferStrileArrayWriting
    TIFFDeferStrileArrayWriting(tiff);

    // Fuzz TIFFForceStrileArrayWriting
    TIFFForceStrileArrayWriting(tiff);

    // Fuzz TIFFIsCODECConfigured
    uint16_t scheme = *reinterpret_cast<const uint16_t*>(Data);
    TIFFIsCODECConfigured(scheme);

    // Fuzz TIFFWriteCheck
    TIFFWriteCheck(tiff, 1, "fuzz_test");

    // Fuzz TIFFIsTiled
    TIFFIsTiled(tiff);

    // Fuzz TIFFWriteDirectory
    TIFFWriteDirectory(tiff);

    closeTIFF(tiff);

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

        LLVMFuzzerTestOneInput_46(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    