#include <sys/stat.h>
#include <string.h>
extern "C" {
    #include "tiffio.h"
    #include <unistd.h>
    #include <fcntl.h>
    #include <sys/types.h>
    #include <sys/stat.h>
    #include <cstdio>
    #include "cstring"
    #include <stdlib.h>  // Include for mkstemp
}

extern "C" int LLVMFuzzerTestOneInput_4(const uint8_t *data, size_t size) {
    // Create a temporary file to write the input data
    char filename[] = "/tmp/fuzz-tiff-XXXXXX";
    int fd = mkstemp(filename);
    if (fd == -1) {
        return 0; // If unable to create a temp file, return early
    }

    // Write the input data to the temporary file
    if (write(fd, data, size) != static_cast<ssize_t>(size)) {
        close(fd);
        unlink(filename);
        return 0; // If unable to write all data, return early
    }
    close(fd);

    // Open the TIFF file using the input data
    TIFF *tiff = TIFFOpen(filename, "r");
    if (tiff != NULL) {
        // Perform operations on the TIFF file to increase code coverage
        uint32_t width, height;
        uint16_t samplesPerPixel, bitsPerSample;
        
        TIFFGetField(tiff, TIFFTAG_IMAGEWIDTH, &width);
        TIFFGetField(tiff, TIFFTAG_IMAGELENGTH, &height);
        TIFFGetField(tiff, TIFFTAG_SAMPLESPERPIXEL, &samplesPerPixel);
        TIFFGetField(tiff, TIFFTAG_BITSPERSAMPLE, &bitsPerSample);

        // Read the image data
        tsize_t scanlineSize = TIFFScanlineSize(tiff);
        tdata_t buf = _TIFFmalloc(scanlineSize);
        if (buf) {
            for (uint32_t row = 0; row < height; row++) {
                TIFFReadScanline(tiff, buf, row);
            }
            _TIFFfree(buf);
        }

        TIFFClose(tiff);
    }

    // Clean up: remove the temporary file
    unlink(filename);

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

    LLVMFuzzerTestOneInput_4(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
