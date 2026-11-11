#include <cstdint>
#include <cstdio>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <cstdlib>  // Include this header for mkstemp

extern "C" {
    #include <tiffio.h>
}

extern "C" int LLVMFuzzerTestOneInput_8(const uint8_t *data, size_t size) {
    TIFF *tiff = nullptr;
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(tmpl);

    if (fd == -1) {
        return 0;
    }

    // Write data to the temporary file
    if (write(fd, data, size) != (ssize_t)size) {
        close(fd);
        unlink(tmpl);
        return 0;
    }

    // Open the TIFF file
    tiff = TIFFOpen(tmpl, "r");
    if (tiff != nullptr) {
        // Attempt to read some data from the TIFF file
        uint32_t width, height;
        uint16_t bitsPerSample, samplesPerPixel;

        if (TIFFGetField(tiff, TIFFTAG_IMAGEWIDTH, &width) &&
            TIFFGetField(tiff, TIFFTAG_IMAGELENGTH, &height) &&
            TIFFGetField(tiff, TIFFTAG_BITSPERSAMPLE, &bitsPerSample) &&
            TIFFGetField(tiff, TIFFTAG_SAMPLESPERPIXEL, &samplesPerPixel)) {
            // Successfully retrieved some TIFF fields
        }

        // Clean up
        TIFFClose(tiff);
    }

    close(fd);
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

    LLVMFuzzerTestOneInput_8(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
