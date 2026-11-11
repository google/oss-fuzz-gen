#include <tiffio.h>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <unistd.h>  // Include for unlink, close, and write
#include <fcntl.h>   // Include for mkstemp

extern "C" int LLVMFuzzerTestOneInput_84(const uint8_t *data, size_t size) {
    // Create a temporary file to store the TIFF data
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        return 0;
    }

    // Write the fuzz data to the temporary file
    if (write(fd, data, size) != (ssize_t)size) {
        close(fd);
        unlink(tmpl);
        return 0;
    }
    close(fd);

    // Open the TIFF file
    TIFF *tif = TIFFOpen(tmpl, "r");
    if (tif == nullptr) {
        unlink(tmpl);
        return 0;
    }

    // Read necessary parameters for TIFFReadScanline
    uint32_t width, height;
    uint16_t samplesPerPixel, bitsPerSample;
    if (!TIFFGetField(tif, TIFFTAG_IMAGEWIDTH, &width) ||
        !TIFFGetField(tif, TIFFTAG_IMAGELENGTH, &height) ||
        !TIFFGetField(tif, TIFFTAG_SAMPLESPERPIXEL, &samplesPerPixel) ||
        !TIFFGetField(tif, TIFFTAG_BITSPERSAMPLE, &bitsPerSample)) {
        TIFFClose(tif);
        unlink(tmpl);
        return 0;
    }

    // Calculate the size of a scanline
    tsize_t scanlineSize = TIFFScanlineSize(tif);
    if (scanlineSize == 0) {
        TIFFClose(tif);
        unlink(tmpl);
        return 0;
    }

    // Allocate memory for a scanline
    void *buf = _TIFFmalloc(scanlineSize);
    if (buf == nullptr) {
        TIFFClose(tif);
        unlink(tmpl);
        return 0;
    }

    // Try to read a scanline
    for (uint32_t row = 0; row < height; ++row) {
        // Attempt to read the scanline
        TIFFReadScanline(tif, buf, row, 0);
    }

    // Clean up
    _TIFFfree(buf);
    TIFFClose(tif);
    unlink(tmpl);

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

    LLVMFuzzerTestOneInput_84(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
