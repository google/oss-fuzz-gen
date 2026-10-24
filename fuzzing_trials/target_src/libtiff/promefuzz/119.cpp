// This fuzz driver is generated for library libtiff, aiming to fuzz the following functions:
// TIFFOpen at tif_unix.c:232:7 in tiffio.h
// TIFFRGBAImageOK at tif_getimage.c:83:5 in tiffio.h
// TIFFErrorExtR at tif_error.c:107:6 in tiffio.h
// TIFFWarningExtR at tif_warning.c:80:6 in tiffio.h
// TIFFWriteCheck at tif_write.c:605:5 in tiffio.h
// TIFFErrorExtR at tif_error.c:107:6 in tiffio.h
// TIFFErrorExtR at tif_error.c:107:6 in tiffio.h
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
#include <cstring>

static TIFF *createDummyTIFF() {
    FILE *file = fopen("./dummy_file", "wb+");
    if (!file) return nullptr;
    fclose(file);
    return TIFFOpen("./dummy_file", "r+");
}

static void testTIFFRGBAImageOK(TIFF *tiff) {
    char emsg[1024];
    int result = TIFFRGBAImageOK(tiff, emsg);
    if (result == 0) {
        TIFFErrorExtR(nullptr, "testTIFFRGBAImageOK", "TIFFRGBAImageOK failed: %s", emsg);
    }
}

static void testTIFFWarningExtR(TIFF *tiff) {
    TIFFWarningExtR(tiff, "testTIFFWarningExtR", "This is a test warning message.");
}

static void testTIFFWriteCheck(TIFF *tiff) {
    int result = TIFFWriteCheck(tiff, 1, "testTIFFWriteCheck");
    if (result == 0) {
        TIFFErrorExtR(nullptr, "testTIFFWriteCheck", "TIFFWriteCheck failed.");
    }
}

static void testTIFFErrorExtR(TIFF *tiff) {
    TIFFErrorExtR(tiff, "testTIFFErrorExtR", "This is a test error message.");
}

extern "C" int LLVMFuzzerTestOneInput_119(const uint8_t *Data, size_t Size) {
    TIFF *tiff = createDummyTIFF();
    if (!tiff) return 0;

    testTIFFRGBAImageOK(tiff);
    testTIFFWarningExtR(tiff);
    testTIFFWriteCheck(tiff);
    testTIFFErrorExtR(tiff);

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

        LLVMFuzzerTestOneInput_119(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    