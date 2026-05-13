#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <unistd.h>  // Include this header for the 'close' function

extern "C" {
    #include <tiffio.h>

    // Function to be used as a dummy TIFFExtendProc
    void dummyTagExtender(TIFF *tiff) {
        // This is a placeholder function for testing purposes.
        // It could be extended to manipulate TIFF tags if needed.
    }

    int LLVMFuzzerTestOneInput_239(const uint8_t *data, size_t size) {
        if (size < 4) {
            // Not enough data to form a valid TIFF header
            return 0;
        }

        // Create a temporary file to write the input data
        char filename[] = "/tmp/libfuzzer_tiff_XXXXXX";
        int fd = mkstemp(filename);
        if (fd == -1) {
            return 0;
        }

        // Write the input data to the temporary file
        FILE *file = fdopen(fd, "wb");
        if (!file) {
            close(fd);
            return 0;
        }
        fwrite(data, 1, size, file);
        fclose(file);

        // Open the TIFF file using libtiff
        TIFF *tiff = TIFFOpen(filename, "r");
        if (tiff) {
            // Process the TIFF file (e.g., read directories, tags, etc.)
            uint32_t width, height;
            uint16_t bitsPerSample, samplesPerPixel;

            TIFFGetField(tiff, TIFFTAG_IMAGEWIDTH, &width);
            TIFFGetField(tiff, TIFFTAG_IMAGELENGTH, &height);
            TIFFGetField(tiff, TIFFTAG_BITSPERSAMPLE, &bitsPerSample);
            TIFFGetField(tiff, TIFFTAG_SAMPLESPERPIXEL, &samplesPerPixel);

            // Close the TIFF file
            TIFFClose(tiff);
        }

        // Clean up the temporary file
        remove(filename);

        return 0;
    }
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

    LLVMFuzzerTestOneInput_239(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
