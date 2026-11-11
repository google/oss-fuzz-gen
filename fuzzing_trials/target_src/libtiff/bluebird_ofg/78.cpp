#include <sys/stat.h>
#include <string.h>
#include "cstdint"
#include "tiffio.h"

extern "C" int LLVMFuzzerTestOneInput_78(const uint8_t *data, size_t size) {
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
    double ret_LogL10toY_zuzzl = LogL10toY(size);
    if (ret_LogL10toY_zuzzl < 0){
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!tiff) {
    	return 0;
    }
    int ret_TIFFDeferStrileArrayWriting_kqpoc = TIFFDeferStrileArrayWriting(tiff);
    if (ret_TIFFDeferStrileArrayWriting_kqpoc < 0){
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!tiff) {
    	return 0;
    }
    tmsize_t ret_TIFFStripSize_solur = TIFFStripSize(tiff);
    // Ensure dataflow is valid (i.e., non-null)
    if (!tiff) {
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!tiff) {
    	return 0;
    }
    tmsize_t ret_TIFFWriteEncodedStrip_cyjaq = TIFFWriteEncodedStrip(tiff, (uint32_t )ret_LogL10toY_zuzzl, (void *)tiff, ret_TIFFStripSize_solur);
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

    LLVMFuzzerTestOneInput_78(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
