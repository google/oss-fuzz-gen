#include <tiffio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h> // Include for close() and unlink()

extern "C" int LLVMFuzzerTestOneInput_180(const uint8_t *data, size_t size) {
    TIFF *tiff;
    uint32_t strip = 0;
    tmsize_t result;
    void *buffer;

    // Create a temporary file for the TIFF image
    char tmpl[] = "/tmp/fuzz_tiffXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        return 0;
    }

    // Open the TIFF file
    tiff = TIFFFdOpen(fd, tmpl, "w+");
    if (!tiff) {
        close(fd);
        unlink(tmpl);
        return 0;
    }

    // Set some basic TIFF tags
    TIFFSetField(tiff, TIFFTAG_IMAGEWIDTH, 1);
    TIFFSetField(tiff, TIFFTAG_IMAGELENGTH, 1);
    TIFFSetField(tiff, TIFFTAG_SAMPLESPERPIXEL, 1);
    TIFFSetField(tiff, TIFFTAG_BITSPERSAMPLE, 8);
    TIFFSetField(tiff, TIFFTAG_ROWSPERSTRIP, 1);
    TIFFSetField(tiff, TIFFTAG_COMPRESSION, COMPRESSION_NONE);
    TIFFSetField(tiff, TIFFTAG_PHOTOMETRIC, PHOTOMETRIC_MINISBLACK);

    // Allocate a buffer for the strip data
    buffer = malloc(size);
    if (!buffer) {
        TIFFClose(tiff);
        close(fd);
        unlink(tmpl);
        return 0;
    }

    // Copy the input data to the buffer
    memcpy(buffer, data, size);

    // Ensure the input data is not empty and write it to the strip
    if (size > 0) {
        result = TIFFWriteEncodedStrip(tiff, strip, buffer, (tmsize_t)size);
        if (result == -1) {
            free(buffer);
            TIFFClose(tiff);
            close(fd);
            unlink(tmpl);
            return 0;
        }
    }

    // Read the data back to ensure it is processed
    void *read_buffer = malloc(size);
    if (read_buffer && size > 0) {
        if (TIFFReadEncodedStrip(tiff, strip, read_buffer, (tmsize_t)size) == -1) {
            free(read_buffer);
            free(buffer);
            TIFFClose(tiff);
            close(fd);
            unlink(tmpl);
            return 0;
        }
        // Optionally, perform additional operations on read_buffer here
        free(read_buffer);
    }

    // Clean up
    free(buffer);
    TIFFClose(tiff);
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

    LLVMFuzzerTestOneInput_180(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
