#include <sys/stat.h>
#include <string.h>
#include "cstdint"
#include "tiffio.h"

extern "C" int LLVMFuzzerTestOneInput_14(const uint8_t *data, size_t size) {
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

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from TIFFOpen to TIFFWriteEncodedStrip
    // Ensure dataflow is valid (i.e., non-null)
    if (!tiff) {
    	return 0;
    }
    int ret_TIFFRewriteDirectory_rmuqw = TIFFRewriteDirectory(tiff);
    if (ret_TIFFRewriteDirectory_rmuqw < 0){
    	return 0;
    }
    double ret_LogL16toY_cpnhw = LogL16toY(0);
    if (ret_LogL16toY_cpnhw < 0){
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!tiff) {
    	return 0;
    }
    tmsize_t ret_TIFFTileRowSize_uymmk = TIFFTileRowSize(tiff);
    // Ensure dataflow is valid (i.e., non-null)
    if (!tiff) {
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!tiff) {
    	return 0;
    }
    tmsize_t ret_TIFFWriteEncodedStrip_dgwje = TIFFWriteEncodedStrip(tiff, (uint32_t )ret_LogL16toY_cpnhw, (void *)tiff, ret_TIFFTileRowSize_uymmk);
    // End mutation: Producer.APPEND_MUTATOR
    
    uint32_t field_tag = *reinterpret_cast<const uint32_t*>(data);

    // Call the function-under-test
    TIFFUnsetField(tiff, field_tag);

    // Close the TIFF structure
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

    LLVMFuzzerTestOneInput_14(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
