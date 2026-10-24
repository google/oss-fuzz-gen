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

extern "C" int LLVMFuzzerTestOneInput_44(const uint8_t *Data, size_t Size) {
    // Write the input data to a dummy file
    FILE *file = fopen("./dummy_file", "wb");
    if (!file) {
        return 0;
    }
    fwrite(Data, 1, Size, file);
    fclose(file);

    // Open the TIFF file
    TIFF *tif = TIFFOpen("./dummy_file", "r");
    if (!tif) {
        return 0;
    }

    // Fuzz TIFFGetWriteProc
    TIFFReadWriteProc writeProc = TIFFGetWriteProc(tif);

    // Fuzz TIFFGetUnmapFileProc
    TIFFUnmapFileProc unmapFileProc = TIFFGetUnmapFileProc(tif);

    // Fuzz TIFFReadDirectory
    int readDirResult = TIFFReadDirectory(tif);

    // Fuzz TIFFGetReadProc
    TIFFReadWriteProc readProc = TIFFGetReadProc(tif);

    // Fuzz TIFFGetSeekProc
    TIFFSeekProc seekProc = TIFFGetSeekProc(tif);

    // Fuzz TIFFSetSubDirectory
    if (Size >= sizeof(uint64_t)) {
        uint64_t offset;
        memcpy(&offset, Data, sizeof(uint64_t));
        int setSubDirResult = TIFFSetSubDirectory(tif, offset);
    }

    // Cleanup
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

    LLVMFuzzerTestOneInput_44(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
