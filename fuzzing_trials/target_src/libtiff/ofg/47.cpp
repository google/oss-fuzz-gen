#include <cstdint>
#include <cstdlib>
#include <tiffio.h>  // Make sure to include the necessary TIFF library headers

extern "C" {
    // Function signatures from the task
    void* _TIFFcalloc(tmsize_t nmemb, tmsize_t size);
    void _TIFFfree(void* p);

    // TIFF function declarations
    TIFF* TIFFClientOpen(const char*, const char*, thandle_t,
                         TIFFReadWriteProc, TIFFReadWriteProc,
                         TIFFSeekProc, TIFFCloseProc, TIFFSizeProc,
                         TIFFMapFileProc, TIFFUnmapFileProc);
    int TIFFSetField(TIFF*, uint32_t, ...);
    int TIFFWriteScanline(TIFF*, void*, uint32_t, uint16_t);
    void TIFFClose(TIFF*);
}

extern "C" int LLVMFuzzerTestOneInput_47(const uint8_t *data, size_t size) {
    // Declare and initialize variables for the _TIFFcalloc function
    tmsize_t nmemb = 1;
    tmsize_t element_size = 1;

    // Ensure we have enough data to derive meaningful sizes
    if (size >= 2) {
        nmemb = static_cast<tmsize_t>(data[0]) + 1;  // Avoid zero nmemb
        element_size = static_cast<tmsize_t>(data[1]) + 1;  // Avoid zero size
    }

    // Call the function-under-test
    void* result = _TIFFcalloc(nmemb, element_size);

    // Use the allocated memory to create a TIFF image
    if (result != nullptr) {
        // Create a TIFF memory stream
        TIFF* tiff = TIFFClientOpen("MemTIFF", "w", reinterpret_cast<thandle_t>(result),
                                    [](thandle_t, void*, tmsize_t) -> tmsize_t { return 0; },
                                    [](thandle_t, void*, tmsize_t) -> tmsize_t { return 0; },
                                    [](thandle_t, toff_t, int) -> toff_t { return 0; },
                                    [](thandle_t) -> int { return 0; },
                                    [](thandle_t) -> toff_t { return 0; },
                                    [](thandle_t, void**, toff_t*) -> int { return 0; },
                                    [](thandle_t, void*, toff_t) -> void {});

        if (tiff) {
            // Perform some operations on the TIFF image
            TIFFSetField(tiff, TIFFTAG_IMAGEWIDTH, 1);
            TIFFSetField(tiff, TIFFTAG_IMAGELENGTH, 1);
            TIFFSetField(tiff, TIFFTAG_SAMPLESPERPIXEL, 1);
            TIFFSetField(tiff, TIFFTAG_BITSPERSAMPLE, 8);
            TIFFSetField(tiff, TIFFTAG_ORIENTATION, ORIENTATION_TOPLEFT);
            TIFFSetField(tiff, TIFFTAG_PLANARCONFIG, PLANARCONFIG_CONTIG);
            TIFFSetField(tiff, TIFFTAG_PHOTOMETRIC, PHOTOMETRIC_MINISBLACK);

            // Write a single pixel
            uint8_t pixel = 0;
            TIFFWriteScanline(tiff, &pixel, 0, 0);

            // Close the TIFF image
            TIFFClose(tiff);
        }

        // Free the allocated memory to prevent memory leaks
        _TIFFfree(result);
    }

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

    LLVMFuzzerTestOneInput_47(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
