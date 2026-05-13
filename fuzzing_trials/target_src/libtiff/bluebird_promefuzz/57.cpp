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
#include <cstdio>
#include "cstdlib"
#include "cstdint"
#include "cstring"

static TIFF* initializeTIFF(const char* filename) {
    TIFF* tif = TIFFOpen(filename, "w");
    if (!tif) {
        fprintf(stderr, "Failed to open TIFF file.\n");
        return nullptr;
    }
    return tif;
}

static void cleanupTIFF(TIFF* tif) {
    if (tif) {
        TIFFClose(tif);
    }
}

static void testTIFFVSetField(TIFF* tif, uint32_t tag, ...) {
    va_list args;
    va_start(args, tag);
    TIFFVSetField(tif, tag, args);
    va_end(args);
}

static void testTIFFUnsetField(TIFF* tif, uint32_t tag) {
    TIFFUnsetField(tif, tag);
}

static void testTIFFCurrentDirectory(TIFF* tif) {
    TIFFCurrentDirectory(tif);
}

static void testTIFFGetTagListCount(TIFF* tif) {
    TIFFGetTagListCount(tif);
}

static void testTIFFCheckTile(TIFF* tif, uint32_t x, uint32_t y, uint32_t z, uint16_t s) {
    TIFFCheckTile(tif, x, y, z, s);
}

static void testTIFFFindField(TIFF* tif, uint32_t tag, TIFFDataType type) {
    TIFFFindField(tif, tag, type);
}

extern "C" int LLVMFuzzerTestOneInput_57(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(uint32_t)) {
        return 0;
    }

    FILE* file = fopen("./dummy_file", "wb");
    if (!file) {
        return 0;
    }
    fwrite(Data, 1, Size, file);
    fclose(file);

    TIFF* tif = initializeTIFF("./dummy_file");
    if (!tif) {
        return 0;
    }

    uint32_t tag = *reinterpret_cast<const uint32_t*>(Data);
    TIFFDataType type = static_cast<TIFFDataType>(Data[Size % sizeof(TIFFDataType)]);

    testTIFFVSetField(tif, tag);
    testTIFFUnsetField(tif, tag);
    testTIFFCurrentDirectory(tif);
    testTIFFGetTagListCount(tif);
    testTIFFCheckTile(tif, tag, tag, tag, static_cast<uint16_t>(tag));
    testTIFFFindField(tif, tag, type);

    cleanupTIFF(tif);
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

    LLVMFuzzerTestOneInput_57(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
