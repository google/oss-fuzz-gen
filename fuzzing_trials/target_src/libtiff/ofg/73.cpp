#include <tiffio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h> // Include for unlink and close functions

extern "C" int LLVMFuzzerTestOneInput_73(const uint8_t *data, size_t size) {
    // Ensure size is sufficient for creating a valid string
    if (size < 1) {
        return 0;
    }

    // Create a temporary file to act as a TIFF file
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        return 0;
    }

    // Initialize TIFF structure
    TIFF *tiff = TIFFOpen(tmpl, "w");
    if (tiff == NULL) {
        close(fd);
        return 0;
    }

    // Ensure the string is null-terminated
    char *mode = (char *)malloc(size + 1);
    if (mode == NULL) {
        TIFFClose(tiff);
        close(fd);
        return 0;
    }
    memcpy(mode, data, size);
    mode[size] = '\0';

    // Call the function-under-test
    TIFFWriteCheck(tiff, 1, mode);

    // Additional operations to increase code coverage
    TIFFSetField(tiff, TIFFTAG_IMAGEWIDTH, 1);
    TIFFSetField(tiff, TIFFTAG_IMAGELENGTH, 1);
    TIFFSetField(tiff, TIFFTAG_SAMPLESPERPIXEL, 1);
    TIFFSetField(tiff, TIFFTAG_BITSPERSAMPLE, 8);
    TIFFSetField(tiff, TIFFTAG_ORIENTATION, ORIENTATION_TOPLEFT);
    TIFFSetField(tiff, TIFFTAG_PLANARCONFIG, PLANARCONFIG_CONTIG);
    TIFFSetField(tiff, TIFFTAG_PHOTOMETRIC, PHOTOMETRIC_MINISBLACK);

    // Write some dummy data to the TIFF file
    uint8_t buffer[1] = {0};
    TIFFWriteEncodedStrip(tiff, 0, buffer, sizeof(buffer));

    // Clean up
    free(mode);
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

    LLVMFuzzerTestOneInput_73(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
