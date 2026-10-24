#include <sys/stat.h>
#include <string.h>
#include "cstdint"
#include "tiffio.h"

extern "C" int LLVMFuzzerTestOneInput_95(const uint8_t *data, size_t size) {
    // Ensure there is enough data to extract a uint32_t value
    if (size < sizeof(uint32_t)) {
        return 0;
    }

    // Create a TIFF structure
    TIFF *tiff = TIFFOpen("/tmp/fuzzfileXXXXXX", "w");
    if (tiff == nullptr) {
        return 0;
    }

    // Extract a uint32_t value from the input data
    uint32_t field_tag = *reinterpret_cast<const uint32_t*>(data);

    // Call the function-under-test
    TIFFUnsetField(tiff, field_tag);

    // Close the TIFF structure

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from TIFFUnsetField to _TIFFmemcmp
    // Ensure dataflow is valid (i.e., non-null)
    if (!tiff) {
    	return 0;
    }
    TIFFReadWriteProc ret_TIFFGetReadProc_tnyvm = TIFFGetReadProc(tiff);
    // Ensure dataflow is valid (i.e., non-null)
    if (!tiff) {
    	return 0;
    }
    tmsize_t ret_TIFFTileRowSize_ozysw = TIFFTileRowSize(tiff);
    // Ensure dataflow is valid (i.e., non-null)
    if (!tiff) {
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!tiff) {
    	return 0;
    }
    int ret__TIFFmemcmp_uvujm = _TIFFmemcmp((const void *)tiff, (const void *)tiff, ret_TIFFTileRowSize_ozysw);
    if (ret__TIFFmemcmp_uvujm < 0){
    	return 0;
    }
    // End mutation: Producer.APPEND_MUTATOR
    
    TIFFClose(tiff);

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

    LLVMFuzzerTestOneInput_95(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
