#include <sys/stat.h>
#include <string.h>
extern "C" {
#include "tiffio.h"
}

#include <cstdio>     // For remove
#include "cstdlib"    // For mkstemp
#include <unistd.h>   // For close
#include "cstring"    // For memcpy
#include "cstdint"    // For uint8_t, uint32_t

extern "C" int LLVMFuzzerTestOneInput_2(const uint8_t *data, size_t size) {
    if (size < sizeof(toff_t) + sizeof(uint32_t) * 6) {
        return 0; // Not enough data to extract required values
    }

    // Create a temporary TIFF file for testing
    char tmpl[] = "/tmp/fuzz_tiffXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        return 0; // Failed to create a temporary file
    }
    close(fd);

    // Open the temporary TIFF file
    TIFF *tiff = TIFFOpen(tmpl, "w");
    if (tiff == nullptr) {
        remove(tmpl);
        return 0; // Failed to open TIFF file
    }

    // Extract a toff_t value from the input data
    toff_t offset = 0;
    memcpy(&offset, data, sizeof(toff_t));

    // Call the function-under-test
    TIFFSetWriteOffset(tiff, offset);

    // Dynamically set some fields based on input data
    uint32_t imageWidth, imageLength, samplesPerPixel, bitsPerSample, orientation, planarConfig;
    memcpy(&imageWidth, data + sizeof(toff_t), sizeof(uint32_t));
    memcpy(&imageLength, data + sizeof(toff_t) + sizeof(uint32_t), sizeof(uint32_t));
    memcpy(&samplesPerPixel, data + sizeof(toff_t) + 2 * sizeof(uint32_t), sizeof(uint32_t));
    memcpy(&bitsPerSample, data + sizeof(toff_t) + 3 * sizeof(uint32_t), sizeof(uint32_t));
    memcpy(&orientation, data + sizeof(toff_t) + 4 * sizeof(uint32_t), sizeof(uint32_t));
    memcpy(&planarConfig, data + sizeof(toff_t) + 5 * sizeof(uint32_t), sizeof(uint32_t));

    TIFFSetField(tiff, TIFFTAG_IMAGEWIDTH, imageWidth % 1000 + 1);
    TIFFSetField(tiff, TIFFTAG_IMAGELENGTH, imageLength % 1000 + 1);
    TIFFSetField(tiff, TIFFTAG_SAMPLESPERPIXEL, samplesPerPixel % 4 + 1);
    TIFFSetField(tiff, TIFFTAG_BITSPERSAMPLE, bitsPerSample % 16 + 1);
    TIFFSetField(tiff, TIFFTAG_ORIENTATION, orientation % 8 + 1);
    TIFFSetField(tiff, TIFFTAG_PLANARCONFIG, planarConfig % 2 + 1);
    TIFFSetField(tiff, TIFFTAG_PHOTOMETRIC, PHOTOMETRIC_MINISBLACK);

    // Write more data to the image
    size_t pixelDataSize = size - sizeof(toff_t) - 6 * sizeof(uint32_t);
    if (pixelDataSize > 0) {
        // Cast the const uint8_t* to void* as TIFFWriteEncodedStrip expects a void* for data
        if (TIFFWriteEncodedStrip(tiff, 0, (void *)(data + sizeof(toff_t) + 6 * sizeof(uint32_t)), pixelDataSize) == -1) {
            TIFFClose(tiff);
            remove(tmpl);
            return 0; // Failed to write data
        }
    }

    // Attempt to read the data back to ensure the file was written correctly
    TIFFClose(tiff);
    tiff = TIFFOpen(tmpl, "r");
    if (tiff != nullptr) {
        // Attempt to read back the image width as a basic check
        uint32_t width = 0;
        TIFFGetField(tiff, TIFFTAG_IMAGEWIDTH, &width);
        TIFFClose(tiff);
    }

    // Clean up
    remove(tmpl);

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

    LLVMFuzzerTestOneInput_2(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
