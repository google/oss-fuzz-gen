#include <cstdint>
#include <cstdlib>
#include <tiffio.h>
#include <cstdio>
#include <cstring>
#include <unistd.h> // Include for POSIX functions like write, close, unlink

extern "C" {
    // Include necessary C headers, source files, functions, and code here.
    void TIFFOpenOptionsFree(TIFFOpenOptions *);
    TIFFOpenOptions *TIFFOpenOptionsAlloc();
}

extern "C" int LLVMFuzzerTestOneInput_161(const uint8_t *data, size_t size) {
    // Create a temporary file to hold the input data
    char tmpFileName[] = "/tmp/fuzz_tiff_XXXXXX";
    int fd = mkstemp(tmpFileName);
    if (fd == -1) {
        return 0; // Failed to create a temporary file
    }

    // Write the input data to the temporary file
    if (write(fd, data, size) != (ssize_t)size) {
        close(fd);
        unlink(tmpFileName);
        return 0; // Failed to write data to the file
    }
    close(fd);

    TIFFOpenOptions *options = TIFFOpenOptionsAlloc();
    if (options == nullptr) {
        unlink(tmpFileName);
        return 0; // Allocation failed, exit early.
    }

    // Open the TIFF file using the input data
    TIFF *tif = TIFFOpen(tmpFileName, "r");
    if (tif) {
        // Perform some basic operations to increase code coverage
        uint32_t width, height; // Use uint32_t instead of deprecated uint32
        TIFFGetField(tif, TIFFTAG_IMAGEWIDTH, &width);
        TIFFGetField(tif, TIFFTAG_IMAGELENGTH, &height);

        // Close the TIFF file
        TIFFClose(tif);
    }

    TIFFOpenOptionsFree(options);

    // Clean up the temporary file
    unlink(tmpFileName);

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

    LLVMFuzzerTestOneInput_161(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
