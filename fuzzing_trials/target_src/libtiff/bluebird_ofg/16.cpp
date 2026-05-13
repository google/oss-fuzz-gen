#include <sys/stat.h>
#include <string.h>
extern "C" {
    #include "tiffio.h"
    #include <unistd.h>
}

#include "cstdint"
#include "cstdlib"
#include <cstdio>

extern "C" int LLVMFuzzerTestOneInput_16(const uint8_t *data, size_t size) {
    // Create a temporary file to store the TIFF data
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        return 0;
    }

    // Write the input data to the temporary file
    FILE *file = fdopen(fd, "wb");
    if (file == nullptr) {
        close(fd);
        return 0;
    }
    fwrite(data, 1, size, file);
    fclose(file);

    // Open the TIFF file
    TIFF *tiff = TIFFOpen(tmpl, "r");
    if (tiff == nullptr) {
        remove(tmpl);
        return 0;
    }

    // Check if the TIFF file has at least one tile
    if (!TIFFIsTiled(tiff)) {
        TIFFClose(tiff);
        remove(tmpl);
        return 0;
    }

    // Get the tile size
    uint32_t tileWidth, tileLength;
    TIFFGetField(tiff, TIFFTAG_TILEWIDTH, &tileWidth);
    TIFFGetField(tiff, TIFFTAG_TILELENGTH, &tileLength);

    // Ensure the raster is large enough to hold the tile
    uint32_t *raster = (uint32_t *)_TIFFmalloc(tileWidth * tileLength * sizeof(uint32_t));
    if (raster == nullptr) {
        TIFFClose(tiff);
        remove(tmpl);
        return 0;
    }

    // Define parameters for TIFFReadRGBATileExt
    uint32_t x = 0;
    uint32_t y = 0;
    int stopOnError = 1;

    // Call the function-under-test
    if (TIFFReadRGBATileExt(tiff, x, y, raster, stopOnError)) {
        // Successfully read the tile
    }

    // Clean up
    _TIFFfree(raster);
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

    LLVMFuzzerTestOneInput_16(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
