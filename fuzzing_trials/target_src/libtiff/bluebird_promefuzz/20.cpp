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

static TIFF* createDummyTIFF(const uint8_t *Data, size_t Size) {
    FILE *file = fopen("./dummy_file", "wb");
    if (!file) {
        return nullptr;
    }

    fwrite(Data, 1, Size, file);
    fclose(file);

    TIFF *tif = TIFFOpen("./dummy_file", "r");

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from TIFFOpen to TIFFDefaultStripSize
    // Ensure dataflow is valid (i.e., non-null)
    if (!tif) {
    	return 0;
    }

    // Begin mutation: Producer.SPLICE_MUTATOR - Spliced data flow from TIFFOpen to TIFFReadDirectory using the plateau pool
    // Ensure dataflow is valid (i.e., non-null)
    if (!tif) {
    	return 0;
    }
    int ret_TIFFReadDirectory_kgwwv = TIFFReadDirectory(tif);
    if (ret_TIFFReadDirectory_kgwwv < 0){
    	return 0;
    }
    // End mutation: Producer.SPLICE_MUTATOR
    
    uint64_t ret_TIFFTileRowSize64_qsfbn = TIFFTileRowSize64(tif);
    if (ret_TIFFTileRowSize64_qsfbn < 0){
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!tif) {
    	return 0;
    }
    uint32_t ret_TIFFDefaultStripSize_oxixn = TIFFDefaultStripSize(tif, (uint32_t )ret_TIFFTileRowSize64_qsfbn);
    if (ret_TIFFDefaultStripSize_oxixn < 0){
    	return 0;
    }
    // End mutation: Producer.APPEND_MUTATOR
    
    return tif;
}

static void cleanupTIFF(TIFF *tif) {
    if (tif) {
        TIFFClose(tif);
    }
}

extern "C" int LLVMFuzzerTestOneInput_20(const uint8_t *Data, size_t Size) {
    if (Size < 1) {
        return 0;
    }

    TIFF *tif = createDummyTIFF(Data, Size);
    if (!tif) {
        return 0;
    }

    // Fuzz TIFFRasterScanlineSize64
    uint64_t rasterScanlineSize = TIFFRasterScanlineSize64(tif);

    // Fuzz TIFFGetStrileByteCount
    uint32_t strileIndex = Data[0] % 10; // Simple modulo to get a valid index
    uint64_t strileByteCount = TIFFGetStrileByteCount(tif, strileIndex);

    // Fuzz TIFFStripSize64
    uint64_t stripSize = TIFFStripSize64(tif);

    // Fuzz TIFFTileSize64
    uint64_t tileSize = TIFFTileSize64(tif);

    // Fuzz TIFFVStripSize64
    uint32_t nrows = (Size > 1) ? Data[1] : 1;
    uint64_t vStripSize = TIFFVStripSize64(tif, nrows);

    // Fuzz TIFFScanlineSize64
    uint64_t scanlineSize = TIFFScanlineSize64(tif);

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

    LLVMFuzzerTestOneInput_20(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
