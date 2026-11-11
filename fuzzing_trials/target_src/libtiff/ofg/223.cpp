#include <cstdint>
#include <cstdlib>
#include <cstdio>
#include <unistd.h>
#include <fcntl.h>

extern "C" {
    #include <tiffio.h>
}

extern "C" int LLVMFuzzerTestOneInput_223(const uint8_t *data, size_t size) {
    if (size < 1) {
        return 0;
    }

    TIFF *tiff = nullptr;
    toff_t offset = 0;

    // Create a temporary file for TIFF operations
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        return 0;
    }

    // Initialize a TIFF structure using the temporary file
    tiff = TIFFOpen(tmpl, "w");
    if (tiff == nullptr) {
        close(fd);
        unlink(tmpl);
        return 0;
    }

    // Write some initial data to the TIFF file to ensure it's not empty
    TIFFSetField(tiff, TIFFTAG_IMAGEWIDTH, 1);
    TIFFSetField(tiff, TIFFTAG_IMAGELENGTH, 1);
    TIFFSetField(tiff, TIFFTAG_SAMPLESPERPIXEL, 1);
    TIFFSetField(tiff, TIFFTAG_BITSPERSAMPLE, 8);
    TIFFSetField(tiff, TIFFTAG_ORIENTATION, ORIENTATION_TOPLEFT);
    TIFFSetField(tiff, TIFFTAG_PLANARCONFIG, PLANARCONFIG_CONTIG);
    TIFFSetField(tiff, TIFFTAG_PHOTOMETRIC, PHOTOMETRIC_MINISBLACK);

    // Write more data from the input buffer to the TIFF file
    size_t write_size = (size < 1024) ? size : 1024; // Limit to 1024 bytes for safety
    TIFFWriteEncodedStrip(tiff, 0, const_cast<uint8_t*>(data), write_size);

    // Set the offset using the provided data
    if (size >= sizeof(toff_t)) {
        offset = *reinterpret_cast<const toff_t*>(data);
    }

    // Call the function-under-test with a valid operation
    // TIFFSetWriteOffset returns void, so we need to handle it differently
    TIFFSetWriteOffset(tiff, offset);

    // Try reading the directory to increase coverage
    TIFFReadDirectory(tiff);

    // Clean up
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

    LLVMFuzzerTestOneInput_223(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
