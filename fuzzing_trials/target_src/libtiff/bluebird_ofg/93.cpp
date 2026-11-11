#include <sys/stat.h>
#include <string.h>
#include "cstdint"
#include <cstdio>
#include "cstdlib"
#include "cstring"
#include <unistd.h> // Include for close function

extern "C" {
    #include "tiffio.h"
}

extern "C" int LLVMFuzzerTestOneInput_93(const uint8_t *data, size_t size) {
    // Create a temporary file to hold the TIFF data
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
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

    // Set up parameters for TIFFReadRGBAImageOriented
    uint32_t width = 1;
    uint32_t height = 1;
    TIFFGetField(tif, TIFFTAG_IMAGEWIDTH, &width);
    TIFFGetField(tif, TIFFTAG_IMAGELENGTH, &height);

    uint32_t *raster = (uint32_t *)_TIFFmalloc(width * height * sizeof(uint32_t));
    if (!raster) {
        TIFFClose(tif);
        remove(tmpl);
        return 0;
    }

    int orientation = ORIENTATION_TOPLEFT; // Use a valid orientation value
    int stopOnError = 1; // Stop on error

    // Call the function-under-test
    TIFFReadRGBAImageOriented(tif, width, height, raster, orientation, stopOnError);

    // Clean up
    _TIFFfree(raster);
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

    LLVMFuzzerTestOneInput_93(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
