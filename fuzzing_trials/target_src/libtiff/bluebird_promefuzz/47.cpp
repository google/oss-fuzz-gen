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

extern "C" int LLVMFuzzerTestOneInput_47(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Step 1: Allocate TIFFOpenOptions
    TIFFOpenOptions *opts = TIFFOpenOptionsAlloc();
    if (!opts) return 0;

    // Step 2: Set Maximum Cumulative Memory Allocation
    tmsize_t max_mem_alloc = static_cast<tmsize_t>(Data[0]);
    TIFFOpenOptionsSetMaxCumulatedMemAlloc(opts, max_mem_alloc);

    // Step 3: Create a dummy file for testing
    FILE *file = fopen("./dummy_file", "wb");
    if (!file) {
        TIFFOpenOptionsFree(opts);
        return 0;
    }
    fwrite(Data, 1, Size, file);
    fclose(file);

    // Step 4: Open the TIFF file using TIFFOpenExt
    TIFF *tif = TIFFOpenExt("./dummy_file", "r", opts);
    TIFFOpenOptionsFree(opts);

    if (!tif) return 0;

    // Step 5: Attempt to set fields using TIFFSetField
    TIFFSetField(tif, static_cast<uint32_t>(Data[0]), Data[0]);
    if (Size > 1) {
        TIFFSetField(tif, static_cast<uint32_t>(Data[1]), Data[1]);
    }

    // Step 6: Write the directory using TIFFWriteDirectory
    TIFFWriteDirectory(tif);

    // Step 7: Close the TIFF file
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

    LLVMFuzzerTestOneInput_47(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
