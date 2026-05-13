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

extern "C" int LLVMFuzzerTestOneInput_21(const uint8_t *Data, size_t Size) {
    if (Size < 1) {
        return 0;
    }

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

    // Invoke the target functions in the specified order
    // TIFFCurrentDirOffset -> TIFFSetDirectory -> TIFFCurrentDirOffset
    // -> TIFFReadDirectory -> TIFFCurrentDirOffset -> TIFFSetDirectory
    // -> TIFFSetDirectory -> TIFFSetDirectory -> TIFFSetSubDirectory
    // -> TIFFSetSubDirectory -> TIFFSetSubDirectory -> TIFFSetSubDirectory
    // -> TIFFIsBigEndian

    uint64_t offset1 = TIFFCurrentDirOffset(tif);

    tdir_t dirNum = static_cast<tdir_t>(Data[0] % 256);
    TIFFSetDirectory(tif, dirNum);

    uint64_t offset2 = TIFFCurrentDirOffset(tif);

    TIFFReadDirectory(tif);

    uint64_t offset3 = TIFFCurrentDirOffset(tif);

    TIFFSetDirectory(tif, dirNum);
    // Begin mutation: Producer.REPLACE_FUNC_MUTATOR - Replaced function TIFFSetDirectory with TIFFUnlinkDirectory
    TIFFUnlinkDirectory(tif, dirNum);
    // End mutation: Producer.REPLACE_FUNC_MUTATOR
    TIFFSetDirectory(tif, dirNum);

    uint64_t subDirOffset = static_cast<uint64_t>(Size > 8 ? *reinterpret_cast<const uint64_t*>(Data) : 0);
    TIFFSetSubDirectory(tif, subDirOffset);
    TIFFSetSubDirectory(tif, subDirOffset);
    TIFFSetSubDirectory(tif, subDirOffset);
    TIFFSetSubDirectory(tif, subDirOffset);

    int isBigEndian = TIFFIsBigEndian(tif);

    // Clean up
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

    LLVMFuzzerTestOneInput_21(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
