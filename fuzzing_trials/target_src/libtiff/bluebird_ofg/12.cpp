#include <sys/stat.h>
#include <string.h>
#include "tiffio.h"
#include "cstdint"
#include "cstdlib"
#include <cstdio>
#include "cstring"
#include <unistd.h> // Include for 'close'

extern "C" {
    // Include necessary C headers here
    #include "tiffio.h"
}

extern "C" int LLVMFuzzerTestOneInput_12(const uint8_t *data, size_t size) {
    // Create a temporary TIFF file
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        return 0;
    }
    FILE *file = fdopen(fd, "wb+");
    if (!file) {
        close(fd);
        return 0;
    }

    // Write the input data to the temporary file
    fwrite(data, 1, size, file);
    fflush(file);
    fseek(file, 0, SEEK_SET);

    // Open the TIFF file in write mode and write a tile
    TIFF *tiff = TIFFFdOpen(fd, tmpl, "w");
    if (!tiff) {
        fclose(file);
        return 0;
    }

    // Ensure the TIFF has at least one tile
    TIFFSetField(tiff, TIFFTAG_IMAGEWIDTH, 256);
    TIFFSetField(tiff, TIFFTAG_IMAGELENGTH, 256);
    TIFFSetField(tiff, TIFFTAG_TILEWIDTH, 128);
    TIFFSetField(tiff, TIFFTAG_TILELENGTH, 128);
    TIFFSetField(tiff, TIFFTAG_SAMPLESPERPIXEL, 4);
    TIFFSetField(tiff, TIFFTAG_BITSPERSAMPLE, 8);
    TIFFSetField(tiff, TIFFTAG_ORIENTATION, ORIENTATION_TOPLEFT);
    TIFFSetField(tiff, TIFFTAG_PLANARCONFIG, PLANARCONFIG_CONTIG);
    TIFFSetField(tiff, TIFFTAG_PHOTOMETRIC, PHOTOMETRIC_RGB);

    // Allocate a buffer for the tile data
    tmsize_t tile_size = TIFFTileSize(tiff);
    void *tile_data = malloc(tile_size);
    if (!tile_data) {
        TIFFClose(tiff);
        fclose(file);
        return 0;
    }

    // Fill tile data with a pattern
    memset(tile_data, 0xAB, tile_size);

    // Write the tile data
    TIFFWriteEncodedTile(tiff, 0, tile_data, tile_size);

    // Clean up
    free(tile_data);
    TIFFClose(tiff);
    fclose(file);

    // Reopen the TIFF file in read mode to trigger more processing
    tiff = TIFFOpen(tmpl, "r");
    if (tiff) {
        // Read the directory to trigger parsing
        TIFFReadDirectory(tiff);
        TIFFClose(tiff);
    }

    // Remove the temporary file
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

    LLVMFuzzerTestOneInput_12(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
