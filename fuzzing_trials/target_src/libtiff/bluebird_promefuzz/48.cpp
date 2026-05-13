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
#include "tiffio.h"
#include <cstdarg>

static int CustomErrorHandler(TIFF*, void*, const char* module, const char* fmt, va_list ap) {
    vfprintf(stderr, fmt, ap);
    return 0;
}

static int CustomWarningHandler(TIFF*, void*, const char* module, const char* fmt, va_list ap) {
    vfprintf(stderr, fmt, ap);
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput_48(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    FILE *file = fopen("./dummy_file", "wb");
    if (!file) return 0;

    fwrite(Data, 1, Size, file);
    fclose(file);

    TIFFOpenOptions *opts = TIFFOpenOptionsAlloc();
    if (!opts) return 0;

    TIFFOpenOptionsSetErrorHandlerExtR(opts, CustomErrorHandler, nullptr);
    TIFFOpenOptionsSetWarningHandlerExtR(opts, CustomWarningHandler, nullptr);

    TIFF *tif = TIFFOpenExt("./dummy_file", "r", opts);
    if (tif) {
        TIFFWarningExtR(tif, "module", "This is a test warning.");
        TIFFErrorExtR(tif, "module", "This is a test error.");

        TIFFClose(tif);
    }

    TIFFOpenOptionsFree(opts);

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

    LLVMFuzzerTestOneInput_48(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
