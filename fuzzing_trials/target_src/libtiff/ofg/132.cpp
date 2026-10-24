#include <cstdint>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <unistd.h>
#include <tiffio.h>

extern "C" {
    #include <tiffio.h>
}

extern "C" int LLVMFuzzerTestOneInput_132(const uint8_t *data, size_t size) {
    // Ensure we have enough data to proceed
    if (size < sizeof(uint32_t)) {
        return 0;
    }

    // Create a temporary TIFF file
    char tmpl[] = "/tmp/fuzzfileXXXXXX.tiff";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        return 0;
    }
    FILE *file = fdopen(fd, "wb");
    if (!file) {
        close(fd);
        return 0;
    }
    fwrite(data, 1, size, file);
    fclose(file);

    // Open the TIFF file
    TIFF *tif = TIFFOpen(tmpl, "r");
    if (!tif) {
        remove(tmpl);
        return 0;
    }

    // Read the TIFF directory and process tags
    do {
        uint32_t width = 0, height = 0;
        uint16_t bitsPerSample = 0, samplesPerPixel = 0;
        if (TIFFGetField(tif, TIFFTAG_IMAGEWIDTH, &width)) {
            printf("Image Width: %u\n", width);
        }
        if (TIFFGetField(tif, TIFFTAG_IMAGELENGTH, &height)) {
            printf("Image Height: %u\n", height);
        }
        if (TIFFGetField(tif, TIFFTAG_BITSPERSAMPLE, &bitsPerSample)) {
            printf("Bits Per Sample: %u\n", bitsPerSample);
        }
        if (TIFFGetField(tif, TIFFTAG_SAMPLESPERPIXEL, &samplesPerPixel)) {
            printf("Samples Per Pixel: %u\n", samplesPerPixel);
        }

        // Attempt to read image data if dimensions are valid
        if (width > 0 && height > 0) {
            tsize_t scanlineSize = TIFFScanlineSize(tif);
            tdata_t buf = _TIFFmalloc(scanlineSize);
            if (buf) {
                for (uint32_t row = 0; row < height; row++) {
                    if (TIFFReadScanline(tif, buf, row) < 0) {
                        break; // Stop if there's an error reading a scanline
                    }
                }
                _TIFFfree(buf);
            }
        }
    } while (TIFFReadDirectory(tif)); // Move to next directory

    // Clean up
    TIFFClose(tif);
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

    LLVMFuzzerTestOneInput_132(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
