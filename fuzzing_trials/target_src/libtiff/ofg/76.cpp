#include <cstdint>
#include <cstdio>
#include <unistd.h>  // For mkstemp, write, close
#include <cstdlib>   // For remove

extern "C" {
#include <tiffio.h>
}

extern "C" int LLVMFuzzerTestOneInput_76(const uint8_t *data, size_t size) {
    if (size < 4) {
        // Not enough data to be a valid TIFF header
        return 0;
    }

    TIFF *tiff;

    // Create a temporary file to write the fuzz data
    char tmpl[] = "/tmp/fuzzfileXXXXXX.tiff";
    int fd = mkstemp(tmpl);

    if (fd == -1) {
        return 0;
    }

    // Write the fuzz data to the temporary file
    if (write(fd, data, size) != size) {
        close(fd);
        remove(tmpl); // Ensure the temporary file is removed on failure
        return 0;
    }

    // Close the file descriptor
    close(fd);

    // Open the TIFF file
    tiff = TIFFOpen(tmpl, "r");
    if (tiff == NULL) {
        remove(tmpl); // Ensure the temporary file is removed on failure
        return 0;
    }

    // Iterate over all possible directory indices
    do {
        // Perform additional operations to increase code coverage
        uint32_t width = 0, height = 0, bitsPerSample = 0, samplesPerPixel = 0;
        if (TIFFGetField(tiff, TIFFTAG_IMAGEWIDTH, &width) &&
            TIFFGetField(tiff, TIFFTAG_IMAGELENGTH, &height) &&
            TIFFGetField(tiff, TIFFTAG_BITSPERSAMPLE, &bitsPerSample) &&
            TIFFGetField(tiff, TIFFTAG_SAMPLESPERPIXEL, &samplesPerPixel)) {
            // Read some data to further increase coverage
            tsize_t scanlineSize = TIFFScanlineSize(tiff);
            tdata_t buf = _TIFFmalloc(scanlineSize);
            if (buf) {
                for (uint32_t row = 0; row < height; ++row) {
                    if (TIFFReadScanline(tiff, buf, row) == -1) {
                        break; // Stop if we encounter an error
                    }
                }
                _TIFFfree(buf);
            }
        }

        // Attempt to read other tags to increase coverage
        char *artist = NULL;
        if (TIFFGetField(tiff, TIFFTAG_ARTIST, &artist)) {
            // Process artist tag if available
        }

        char *make = NULL;
        if (TIFFGetField(tiff, TIFFTAG_MAKE, &make)) {
            // Process make tag if available
        }

        char *model = NULL;
        if (TIFFGetField(tiff, TIFFTAG_MODEL, &model)) {
            // Process model tag if available
        }

        // Additional operations to increase code coverage
        uint16_t compression;
        if (TIFFGetField(tiff, TIFFTAG_COMPRESSION, &compression)) {
            // Process compression tag if available
        }

        uint16_t photometric;
        if (TIFFGetField(tiff, TIFFTAG_PHOTOMETRIC, &photometric)) {
            // Process photometric tag if available
        }

        uint16_t orientation;
        if (TIFFGetField(tiff, TIFFTAG_ORIENTATION, &orientation)) {
            // Process orientation tag if available
        }

    } while (TIFFReadDirectory(tiff)); // Move to the next directory if available

    // Close the TIFF file
    TIFFClose(tiff);

    // Remove the temporary file
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

    LLVMFuzzerTestOneInput_76(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
