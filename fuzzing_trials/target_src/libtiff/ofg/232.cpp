#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <tiffio.h>

extern "C" {
    // Function to be fuzzed
    void TIFFOpenOptionsSetMaxSingleMemAlloc(TIFFOpenOptions *, tmsize_t);
}

extern "C" int LLVMFuzzerTestOneInput_232(const uint8_t *data, size_t size) {
    // Ensure the size is large enough to extract a tmsize_t value
    if (size < sizeof(tmsize_t)) {
        return 0;
    }

    // Initialize TIFFOpenOptions
    TIFFOpenOptions *options = TIFFOpenOptionsAlloc();
    if (options == NULL) {
        return 0; // Fail gracefully if allocation fails
    }

    // Extract a tmsize_t value from the input data
    tmsize_t maxSingleMemAlloc;
    memcpy(&maxSingleMemAlloc, data, sizeof(tmsize_t));

    // Call the function-under-test
    TIFFOpenOptionsSetMaxSingleMemAlloc(options, maxSingleMemAlloc);

    // Additional operations to ensure coverage
    // For example, using the options in a TIFF operation
    TIFF *tif = TIFFOpen("dummy.tiff", "w");
    if (tif) {
        // Use the options in some meaningful way with TIFF
        TIFFSetField(tif, TIFFTAG_IMAGEWIDTH, 1);
        TIFFSetField(tif, TIFFTAG_IMAGELENGTH, 1);
        TIFFSetField(tif, TIFFTAG_SAMPLESPERPIXEL, 1);
        TIFFSetField(tif, TIFFTAG_BITSPERSAMPLE, 8);
        TIFFSetField(tif, TIFFTAG_ORIENTATION, ORIENTATION_TOPLEFT);
        TIFFSetField(tif, TIFFTAG_PLANARCONFIG, PLANARCONFIG_CONTIG);
        TIFFSetField(tif, TIFFTAG_PHOTOMETRIC, PHOTOMETRIC_MINISBLACK);

        // Write a dummy scanline
        uint8_t scanline[1] = {0};
        TIFFWriteScanline(tif, scanline, 0, 0);

        TIFFClose(tif);
    }

    // Clean up
    TIFFOpenOptionsFree(options);

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

    LLVMFuzzerTestOneInput_232(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
