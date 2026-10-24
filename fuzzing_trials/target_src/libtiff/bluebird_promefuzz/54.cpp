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
#include "cstdlib"
#include "cstring"

static TIFF* initializeTIFF(const char* filename, const char* mode) {
    return TIFFOpen(filename, mode);
}

static void cleanupTIFF(TIFF* tif) {
    if (tif) {
        TIFFClose(tif);
    }
}

extern "C" int LLVMFuzzerTestOneInput_54(const uint8_t *Data, size_t Size) {
    if (Size < 1) {
        return 0;
    }

    // Prepare a dummy file
    const char* dummyFilename = "./dummy_file";
    FILE* file = fopen(dummyFilename, "wb");
    if (!file) {
        return 0;
    }
    fwrite(Data, 1, Size, file);
    fclose(file);

    // Initialize TIFF
    TIFF* tif = initializeTIFF(dummyFilename, "r");
    if (!tif) {
        return 0;
    }

    // Buffer for TIFFReadEncodedStrip
    uint32_t stripIndex = 0;
    tmsize_t bufferSize = 1024; // Arbitrary buffer size
    void* buffer = malloc(bufferSize);
    if (buffer) {
        // Begin mutation: Producer.REPLACE_FUNC_MUTATOR - Replaced function TIFFReadEncodedStrip with TIFFReadRawTile
        TIFFReadRawTile(tif, stripIndex, buffer, bufferSize);
        // End mutation: Producer.REPLACE_FUNC_MUTATOR
        free(buffer);
    }

    // _TIFFmemcpy usage
    if (Size > 1) {
        void* destBuffer = malloc(Size);
        if (destBuffer) {
            _TIFFmemcpy(destBuffer, Data, Size);
            free(destBuffer);
        }
    }

    // TIFFWriteScanline
    if (Size > 2) {
        TIFF* tifWrite = initializeTIFF(dummyFilename, "w");
        if (tifWrite) {
            TIFFWriteScanline(tifWrite, const_cast<uint8_t*>(Data), 0, 0);
            cleanupTIFF(tifWrite);
        }
    }

    // TIFFGetBitRevTable
    const unsigned char* bitRevTable = TIFFGetBitRevTable(1);
    (void)bitRevTable; // Suppress unused variable warning

    // TIFFReverseBits
    if (Size > 3) {
        uint8_t* cp = (uint8_t*)malloc(Size);
        if (cp) {
            memcpy(cp, Data, Size);
            TIFFReverseBits(cp, Size);
            free(cp);
        }
    }

    // TIFFReadGPSDirectory
    if (Size > 4) {
        toff_t diroff = 0;
        TIFFReadGPSDirectory(tif, diroff);
    }

    // Cleanup
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

    LLVMFuzzerTestOneInput_54(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
