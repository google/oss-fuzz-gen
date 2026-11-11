#include <sys/stat.h>
#include <string.h>
#include <iostream>
#include "sstream"
#include <string>
#include <vector>
#include "cstring"
#include "cstdlib"
#include <cstdio>
#include "cstdint"
#include <cstddef>
extern "C" {
#include "tiffio.h"
}

#include "cstdint"
#include <cstdio>

static void CustomErrorHandler(const char* module, const char* fmt, va_list ap) {
    // Custom error handling logic
}

extern "C" int LLVMFuzzerTestOneInput_18(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Create a dummy TIFF file
    FILE *file = fopen("./dummy_file", "wb");
    if (!file) return 0;
    fwrite(Data, 1, Size, file);
    fclose(file);

    // Open the TIFF file
    TIFF *tif = TIFFOpen("./dummy_file", "r+");
    if (!tif) return 0;

    // Variables for function calls
    uint64_t offset = 0;
    tdir_t dirn = 0;
    uint32_t tag = 0;
    int value = 0;

    // Invoke TIFFWriteDirectory
    TIFFWriteDirectory(tif);

    // Invoke TIFFSetSubDirectory
    TIFFSetSubDirectory(tif, offset);

    // Invoke TIFFSetField
    TIFFSetField(tif, tag, value);

    // Set custom error handler
    TIFFErrorHandler prevHandler = TIFFSetErrorHandler(CustomErrorHandler);

    // Invoke TIFFWriteDirectory again
    TIFFWriteDirectory(tif);

    // Restore previous error handler
    TIFFSetErrorHandler(prevHandler);

    // Invoke TIFFSetDirectory
    TIFFSetDirectory(tif, dirn);

    // Invoke TIFFCurrentDirOffset
    TIFFCurrentDirOffset(tif);

    // Invoke TIFFSetDirectory again
    TIFFSetDirectory(tif, dirn);

    // Invoke TIFFCurrentDirOffset again
    TIFFCurrentDirOffset(tif);

    // Invoke TIFFSetSubDirectory again
    TIFFSetSubDirectory(tif, offset);

    // Close the TIFF file
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

    LLVMFuzzerTestOneInput_18(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
