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

extern "C" int LLVMFuzzerTestOneInput_9(const uint8_t *Data, size_t Size) {
    if (Size < 1) {
        return 0;
    }

    // Create a dummy file
    FILE *file = fopen("./dummy_file", "wb");
    if (!file) {
        return 0;
    }
    fwrite(Data, 1, Size, file);
    fclose(file);

    // Open the TIFF file
    TIFF *tif = TIFFOpen("./dummy_file", "r+");
    if (!tif) {
        return 0;
    }

    // Fuzz TIFFForceStrileArrayWriting
    TIFFForceStrileArrayWriting(tif);

    // Fuzz TIFFSetWriteOffset
    if (Size >= sizeof(toff_t)) {
        toff_t offset;
        memcpy(&offset, Data, sizeof(toff_t));
        TIFFSetWriteOffset(tif, offset);
    }

    // Fuzz TIFFFlushData
    TIFFFlushData(tif);

    // Fuzz TIFFIsTiled
    TIFFIsTiled(tif);

    // Fuzz TIFFGetStrileOffsetWithErr
    if (Size >= sizeof(uint32_t)) {
        uint32_t strile;
        memcpy(&strile, Data, sizeof(uint32_t));
        int err;
        TIFFGetStrileOffsetWithErr(tif, strile, &err);
    }

    // Fuzz TIFFReadDirectory
    TIFFReadDirectory(tif);

    // Close the TIFF file

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from TIFFReadDirectory to TIFFComputeStrip
    float iomhwvvc = 64;
    TIFFSwabFloat(&iomhwvvc);
    uint64_t fhbndphk = 64;
    TIFFSwabLong8(&fhbndphk);
    // Ensure dataflow is valid (i.e., non-null)
    if (!tif) {
    	return 0;
    }
    uint32_t ret_TIFFComputeStrip_yiagp = TIFFComputeStrip(tif, (uint32_t )iomhwvvc, (uint16_t )fhbndphk);
    if (ret_TIFFComputeStrip_yiagp < 0){
    	return 0;
    }
    // End mutation: Producer.APPEND_MUTATOR
    
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

    LLVMFuzzerTestOneInput_9(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
