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
#include <cstdio>
#include "cstdlib"
#include "cstring"

static TIFFErrorHandler defaultErrorHandler = nullptr;
static TIFFErrorHandler defaultWarningHandler = nullptr;

static void customErrorHandler(const char* module, const char* fmt, va_list ap) {
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
}

static void customWarningHandler(const char* module, const char* fmt, va_list ap) {
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
}

extern "C" int LLVMFuzzerTestOneInput_6(const uint8_t *Data, size_t Size) {
    if (Size < 1) {
        return 0;
    }

    // Set custom error and warning handlers
    defaultErrorHandler = TIFFSetErrorHandler(customErrorHandler);
    defaultWarningHandler = TIFFSetWarningHandler(customWarningHandler);

    // Create a dummy file to work with
    FILE *file = fopen("./dummy_file", "wb");
    if (!file) {
        return 0;
    }
    fwrite(Data, 1, Size, file);
    fclose(file);

    // Open the dummy file with libtiff
    TIFF *tif = TIFFOpen("./dummy_file", "r+");
    if (!tif) {
        return 0;
    }

    // Fuzzing TIFFCheckpointDirectory
    TIFFCheckpointDirectory(tif);

    // Fuzzing TIFFFlushData

    // Begin mutation: Producer.SPLICE_MUTATOR - Spliced data flow from TIFFCheckpointDirectory to TIFFReadRawTile using the plateau pool
    uint32_t tileIndex = 0;
    tmsize_t bufferSize = 256;
    // Ensure dataflow is valid (i.e., non-null)
    if (!tif) {
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!tif) {
    	return 0;
    }
    tmsize_t ret_TIFFReadRawTile_dfldr = TIFFReadRawTile(tif, tileIndex, (void *)tif, bufferSize);
    // End mutation: Producer.SPLICE_MUTATOR
    
    TIFFFlushData(tif);

    // Fuzzing TIFFWriteDirectory
    TIFFWriteDirectory(tif);

    // Fuzzing TIFFSetDirectory with random directory number
    tdir_t dirNum = static_cast<tdir_t>(Data[0] % 256); // Simple way to get a directory number
    TIFFSetDirectory(tif, dirNum);

    // Cleanup
    TIFFClose(tif);

    // Restore the default handlers
    TIFFSetErrorHandler(defaultErrorHandler);
    TIFFSetWarningHandler(defaultWarningHandler);

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

    LLVMFuzzerTestOneInput_6(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
