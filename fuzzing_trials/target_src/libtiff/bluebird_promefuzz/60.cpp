#include <sys/stat.h>
#include <string.h>
#include <iostream>
#include "cstdint"
#include <cstddef>
#include "tiffio.h"

extern "C" int LLVMFuzzerTestOneInput_60(const uint8_t *Data, size_t Size) {
    if (Size < 4) {
        return 0;
    } // Ensure there's enough data for a minimal operation

    // Create a temporary file to simulate a TIFF file
    FILE *file = fopen("./dummy_file", "wb");
    if (!file) {
        return 0;
    }
    fwrite(Data, 1, Size, file);
    fclose(file);

    // Open the TIFF file
    TIFF *tiff = TIFFOpen("./dummy_file", "r");
    if (!tiff) {
        return 0;
    }

    // Step 1: Check if the TIFF image is tiled
    int tiled = TIFFIsTiled(tiff);

    // Step 2: Allocate memory using _TIFFmalloc
    tmsize_t allocSize1 = 1024; // Arbitrary allocation size
    void *memory1 = _TIFFmalloc(allocSize1);
    if (!memory1) {
        TIFFClose(tiff);
        return 0; // Memory allocation failed
    }

    tmsize_t allocSize2 = 2048; // Another arbitrary allocation size
    void *memory2 = _TIFFmalloc(allocSize2);
    if (!memory2) {
        _TIFFfree(memory1);
        TIFFClose(tiff);
        return 0; // Memory allocation failed
    }

    // Step 3: Initialize a TIFFRGBAImage structure
    TIFFRGBAImage img;
    char emsg[1024];
    if (!TIFFRGBAImageBegin(&img, tiff, 0, emsg)) {
        _TIFFfree(memory1);
        _TIFFfree(memory2);
        TIFFClose(tiff);
        return 0; // Initialization failed
    }

    // Step 4: Retrieve RGBA pixel data into a raster buffer
    uint32_t width = 100; // Arbitrary width
    uint32_t height = 100; // Arbitrary height
    uint32_t *raster = static_cast<uint32_t *>(_TIFFmalloc(width * height * sizeof(uint32_t)));
    if (!raster) {
        TIFFRGBAImageEnd(&img);
        _TIFFfree(memory1);
        _TIFFfree(memory2);
        TIFFClose(tiff);
        return 0; // Memory allocation failed
    }

    if (!TIFFRGBAImageGet(&img, raster, width, height)) {
        _TIFFfree(raster);
        TIFFRGBAImageEnd(&img);

        // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from TIFFRGBAImageEnd to TIFFWriteRawStrip
        double ret_LogL10toY_qvwsy = LogL10toY(TIFF_SPP);
        if (ret_LogL10toY_qvwsy < 0){
        	return 0;
        }
        // Ensure dataflow is valid (i.e., non-null)
        if (!tiff) {
        	return 0;
        }
        tmsize_t ret_TIFFScanlineSize_mowpm = TIFFScanlineSize(tiff);
        // Ensure dataflow is valid (i.e., non-null)
        if (!tiff) {
        	return 0;
        }
        tmsize_t ret_TIFFWriteRawStrip_aspeb = TIFFWriteRawStrip(tiff, (uint32_t )ret_LogL10toY_qvwsy, (void *)&img, ret_TIFFScanlineSize_mowpm);
        // End mutation: Producer.APPEND_MUTATOR
        
        _TIFFfree(memory1);
        _TIFFfree(memory2);
        TIFFClose(tiff);
        return 0; // Failed to get image data
    }

    // Step 5: Clean up
    TIFFRGBAImageEnd(&img);
    _TIFFfree(raster);
    _TIFFfree(memory1);
    _TIFFfree(memory2);
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

    LLVMFuzzerTestOneInput_60(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
