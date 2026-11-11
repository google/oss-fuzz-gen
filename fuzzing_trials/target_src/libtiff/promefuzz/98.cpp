// This fuzz driver is generated for library libtiff, aiming to fuzz the following functions:
// TIFFSetErrorHandlerExt at tif_error.c:39:21 in tiffio.h
// TIFFSetWarningHandlerExt at tif_warning.c:39:21 in tiffio.h
// TIFFError at tif_error.c:46:6 in tiffio.h
// TIFFWarning at tif_warning.c:46:6 in tiffio.h
// TIFFOpen at tif_unix.c:232:7 in tiffio.h
// TIFFErrorExtR at tif_error.c:107:6 in tiffio.h
// TIFFWarningExtR at tif_warning.c:80:6 in tiffio.h
// TIFFClose at tif_close.c:155:6 in tiffio.h
// TIFFSetErrorHandlerExt at tif_error.c:39:21 in tiffio.h
// TIFFSetWarningHandlerExt at tif_warning.c:39:21 in tiffio.h
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <cstdint>
#include <cstddef>
#include <cstdint>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include "tiffio.h"

static void CustomErrorHandler(thandle_t, const char* module, const char* fmt, va_list ap) {
    fprintf(stderr, "Custom Error Handler: ");
    if (module) {
        fprintf(stderr, "%s: ", module);
    }
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
}

static void CustomWarningHandler(thandle_t, const char* module, const char* fmt, va_list ap) {
    fprintf(stderr, "Custom Warning Handler: ");
    if (module) {
        fprintf(stderr, "%s: ", module);
    }
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
}

extern "C" int LLVMFuzzerTestOneInput_98(const uint8_t *Data, size_t Size) {
    if (Size < 1) {
        return 0;
    }

    // Set custom handlers
    TIFFErrorHandlerExt prevErrorHandler = TIFFSetErrorHandlerExt(CustomErrorHandler);
    TIFFErrorHandlerExt prevWarningHandler = TIFFSetWarningHandlerExt(CustomWarningHandler);

    // Test TIFFError
    TIFFError("TestModule", "Error message with code %d", Data[0]);

    // Test TIFFWarning
    TIFFWarning("TestModule", "Warning message with code %d", Data[0]);

    // Create a dummy TIFF object for testing using TIFFOpen
    FILE *dummyFile = fopen("./dummy_file", "wb");
    if (dummyFile) {
        fwrite(Data, 1, Size, dummyFile);
        fclose(dummyFile);

        TIFF* dummyTiff = TIFFOpen("./dummy_file", "r");
        if (dummyTiff) {
            // Test TIFFErrorExtR
            TIFFErrorExtR(dummyTiff, "TestModule", "ErrorExtR message with code %d", Data[0]);

            // Test TIFFWarningExtR
            TIFFWarningExtR(dummyTiff, "TestModule", "WarningExtR message with code %d", Data[0]);

            TIFFClose(dummyTiff);
        }
    }

    // Reset to previous handlers
    TIFFSetErrorHandlerExt(prevErrorHandler);
    TIFFSetWarningHandlerExt(prevWarningHandler);

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

        LLVMFuzzerTestOneInput_98(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    