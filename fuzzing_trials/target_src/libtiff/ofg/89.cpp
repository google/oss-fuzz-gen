#include <cstdint>
#include <cstdio>
#include <cstdlib> // For mkstemp and close
#include <unistd.h> // For mkstemp and close

extern "C" {
    #include <tiffio.h>
}

extern "C" int LLVMFuzzerTestOneInput_89(const uint8_t *data, size_t size) {
    // Create a temporary file to simulate a TIFF file
    char tmpl[] = "/tmp/fuzzfileXXXXXX.tiff";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        return 0;
    }
    FILE* file = fdopen(fd, "wb");
    if (!file) {
        close(fd);
        return 0;
    }

    // Write the fuzz data to the file
    fwrite(data, 1, size, file);
    fclose(file);

    // Open the TIFF file
    TIFF* tiff = TIFFOpen(tmpl, "r");
    if (tiff == nullptr) {
        remove(tmpl);
        return 0;
    }

    do {
        // Attempt to read image data to increase code coverage
        uint32_t width, height;
        uint16_t bitsPerSample, samplesPerPixel;
        if (TIFFGetField(tiff, TIFFTAG_IMAGEWIDTH, &width) &&
            TIFFGetField(tiff, TIFFTAG_IMAGELENGTH, &height) &&
            TIFFGetField(tiff, TIFFTAG_BITSPERSAMPLE, &bitsPerSample) &&
            TIFFGetField(tiff, TIFFTAG_SAMPLESPERPIXEL, &samplesPerPixel)) {

            // Allocate buffer to hold one scanline
            tsize_t scanlineSize = TIFFScanlineSize(tiff);
            tdata_t buf = _TIFFmalloc(scanlineSize);

            if (buf) {
                // Read each scanline
                for (uint32_t row = 0; row < height; row++) {
                    if (TIFFReadScanline(tiff, buf, row) < 0) {
                        break;
                    }
                    // Process the scanline if needed
                    // Example: sum up pixel values or perform a dummy operation
                    for (tsize_t i = 0; i < scanlineSize; i++) {
                        ((uint8_t*)buf)[i] += 1; // Dummy operation
                    }
                }
                _TIFFfree(buf);
            }
        }

        // Additional TIFF operations to increase code coverage
        uint16_t compression;
        if (TIFFGetField(tiff, TIFFTAG_COMPRESSION, &compression)) {
            // Process compression field if needed
        }

        // Additional operations to increase coverage
        uint16_t orientation;
        if (TIFFGetField(tiff, TIFFTAG_ORIENTATION, &orientation)) {
            // Process orientation field if needed
        }

        // Attempt to read EXIF data
        char* exifData;
        if (TIFFGetField(tiff, TIFFTAG_EXIFIFD, &exifData)) {
            // Process EXIF data if needed
        }

    } while (TIFFReadDirectory(tiff)); // Iterate over all directories

    // Cleanup
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

    LLVMFuzzerTestOneInput_89(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
