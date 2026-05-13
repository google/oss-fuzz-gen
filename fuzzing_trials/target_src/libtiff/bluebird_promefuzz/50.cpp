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
#include "cstdint"
#include "cstdlib"
#include <cstdio>
#include <cstdarg>

static TIFFErrorHandler defaultErrorHandler = nullptr;

static void customErrorHandler(const char* module, const char* fmt, va_list ap) {
    if (defaultErrorHandler) {
        defaultErrorHandler(module, fmt, ap);
    }
}

extern "C" int LLVMFuzzerTestOneInput_50(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    FILE *file = fopen("./dummy_file", "wb");
    if (!file) return 0;
    fwrite(Data, 1, Size, file);
    fclose(file);

    TIFF *tif = TIFFOpen("./dummy_file", "r+");
    if (!tif) return 0;

    TIFFWriteDirectory(tif);

    TIFFSetSubDirectory(tif, static_cast<uint64_t>(Data[0]));

    TIFFSetField(tif, static_cast<uint32_t>(Data[0]), static_cast<int>(Data[0]));

    defaultErrorHandler = TIFFSetErrorHandler(customErrorHandler);

    TIFFWriteDirectory(tif);

    TIFFSetErrorHandler(defaultErrorHandler);

    TIFFSetDirectory(tif, static_cast<tdir_t>(Data[0]));

    TIFFCurrentDirOffset(tif);

    TIFFSetDirectory(tif, static_cast<tdir_t>(Data[0]));

    TIFFCurrentDirOffset(tif);

    TIFFSetSubDirectory(tif, static_cast<uint64_t>(Data[0]));

    TIFFClose(tif);
    tif = nullptr;

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

    LLVMFuzzerTestOneInput_50(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
