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

extern "C" int LLVMFuzzerTestOneInput_25(const uint8_t *Data, size_t Size) {
    if (Size < 1) {
        return 0;
    }

    // Create a dummy file to be used by libtiff
    const char *filename = "./dummy_file";
    FILE *file = fopen(filename, "wb");
    if (!file) {
        return 0;
    }
    fwrite(Data, 1, Size, file);
    fclose(file);

    // Open the TIFF file
    TIFF *tif = TIFFOpen(filename, "r+");
    if (!tif) {
        remove(filename);
        return 0;
    }

    // Fuzz TIFFForceStrileArrayWriting
    TIFFForceStrileArrayWriting(tif);

    // Fuzz TIFFIsMSB2LSB
    TIFFIsMSB2LSB(tif);

    // Fuzz TIFFSetupStrips
    TIFFSetupStrips(tif);

    // Fuzz TIFFFileno
    TIFFFileno(tif);

    // Fuzz TIFFGetMode

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from TIFFFileno to TIFFWriteCustomDirectory
    // Ensure dataflow is valid (i.e., non-null)
    if (!tif) {
    	return 0;
    }
    uint64_t ret_TIFFRasterScanlineSize64_fspox = TIFFRasterScanlineSize64(tif);
    if (ret_TIFFRasterScanlineSize64_fspox < 0){
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!tif) {
    	return 0;
    }
    int ret_TIFFWriteCustomDirectory_mmkqf = TIFFWriteCustomDirectory(tif, &ret_TIFFRasterScanlineSize64_fspox);
    if (ret_TIFFWriteCustomDirectory_mmkqf < 0){
    	return 0;
    }
    // End mutation: Producer.APPEND_MUTATOR
    
    TIFFGetMode(tif);

    // Fuzz TIFFIsTiled
    TIFFIsTiled(tif);

    // Clean up
    TIFFClose(tif);
    remove(filename);

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

    LLVMFuzzerTestOneInput_25(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
