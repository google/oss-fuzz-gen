#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <tiffio.h>
#include <unistd.h>  // For close()
#include <cstring>   // For memcpy()

extern "C" {
    // Include necessary C headers, source files, functions, and code here.
    #include <tiffio.h>
}

extern "C" int LLVMFuzzerTestOneInput_252(const uint8_t *data, size_t size) {
    if (size < 3) {
        // Not enough data to set meaningful row, sample, and pixel data
        return 0;
    }

    TIFF *tiff;
    void *buffer;
    uint32_t row;
    uint16_t sample;

    // Create a temporary TIFF file
    char tmpl[] = "/tmp/fuzzfileXXXXXX.tiff";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        return 0;
    }
    close(fd);

    // Open the TIFF file
    tiff = TIFFOpen(tmpl, "w");
    if (!tiff) {
        return 0;
    }

    // Set up a basic TIFF structure
    TIFFSetField(tiff, TIFFTAG_IMAGEWIDTH, 1);
    TIFFSetField(tiff, TIFFTAG_IMAGELENGTH, 1);
    TIFFSetField(tiff, TIFFTAG_SAMPLESPERPIXEL, 1);
    TIFFSetField(tiff, TIFFTAG_BITSPERSAMPLE, 8);
    TIFFSetField(tiff, TIFFTAG_ORIENTATION, ORIENTATION_TOPLEFT);
    TIFFSetField(tiff, TIFFTAG_PLANARCONFIG, PLANARCONFIG_CONTIG);
    TIFFSetField(tiff, TIFFTAG_PHOTOMETRIC, PHOTOMETRIC_MINISBLACK);

    // Initialize buffer, row, and sample
    buffer = malloc(size);
    if (!buffer) {
        TIFFClose(tiff);
        return 0;
    }
    memcpy(buffer, data, size);

    row = data[0] % TIFFNumberOfStrips(tiff); // Use the first byte of data as a row index
    sample = data[1] % TIFFNumberOfStrips(tiff); // Use the second byte of data as a sample index

    // Call the function-under-test
    if (TIFFWriteScanline(tiff, buffer, row, sample) < 0) {
        // Handle error if needed
    }

    // Clean up
    free(buffer);
    TIFFClose(tiff);
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

    LLVMFuzzerTestOneInput_252(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
