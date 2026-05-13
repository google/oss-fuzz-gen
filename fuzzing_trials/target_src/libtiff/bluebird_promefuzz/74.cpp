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

extern "C" int LLVMFuzzerTestOneInput_74(const uint8_t *Data, size_t Size) {
    if (Size < 5) {
        return 0;
    } // Ensure we have enough data for minimal operations

    // Create a dummy TIFF file
    FILE *file = fopen("./dummy_file", "wb+");
    if (!file) {
        return 0;
    }
    fwrite(Data, 1, Size, file);
    fclose(file);

    // Open the dummy TIFF file
    TIFF *tif = TIFFOpen("./dummy_file", "r+");
    if (!tif) {
        return 0;
    }

    // Use the first byte to simulate directory setting

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from TIFFOpen to TIFFSetDirectory
    // Ensure dataflow is valid (i.e., non-null)
    if (!tif) {
    	return 0;
    }
    uint64_t ret_TIFFStripSize64_psmbq = TIFFStripSize64(tif);
    if (ret_TIFFStripSize64_psmbq < 0){
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!tif) {
    	return 0;
    }
    int ret_TIFFSetDirectory_tykiu = TIFFSetDirectory(tif, (uint32_t )ret_TIFFStripSize64_psmbq);
    if (ret_TIFFSetDirectory_tykiu < 0){
    	return 0;
    }
    // End mutation: Producer.APPEND_MUTATOR
    
    tdir_t dirn = Data[0];
    if (!TIFFSetDirectory(tif, dirn)) {
        TIFFClose(tif);
        return 0;
    }

    // Use subsequent bytes as tag and data for TIFFSetField
    uint32_t tag = Data[1];
    uint32_t value = *(reinterpret_cast<const uint32_t*>(&Data[2]));
    if (!TIFFSetField(tif, tag, value)) {
        TIFFClose(tif);
        return 0;
    }

    // Write current directory
    if (!TIFFWriteDirectory(tif)) {
        TIFFClose(tif);
        return 0;
    }

    // Create EXIF directory
    if (!TIFFCreateEXIFDirectory(tif)) {
        TIFFClose(tif);
        return 0;
    }

    // Set multiple fields in EXIF directory
    for (int i = 0; i < 7; ++i) {
        if (!TIFFSetField(tif, tag + i, value + i)) {
            TIFFClose(tif);
            return 0;
        }
    }

    // Write custom directory
    uint64_t offset;
    if (!TIFFWriteCustomDirectory(tif, &offset)) {
        TIFFClose(tif);
        return 0;
    }

    // Reset directory
    if (!TIFFSetDirectory(tif, dirn)) {
        TIFFClose(tif);
        return 0;
    }

    // Set field again
    if (!TIFFSetField(tif, tag, value)) {
        TIFFClose(tif);
        return 0;
    }

    // Write directory again
    if (!TIFFWriteDirectory(tif)) {
        TIFFClose(tif);
        return 0;
    }

    // Close the TIFF file
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

    LLVMFuzzerTestOneInput_74(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
