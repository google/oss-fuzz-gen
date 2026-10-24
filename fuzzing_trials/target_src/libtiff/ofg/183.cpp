#include <tiffio.h>
#include <cstdint>
#include <cstdlib>
#include <cstdio>
#include <unistd.h>  // Include this header for the 'close' function

extern "C" int LLVMFuzzerTestOneInput_183(const uint8_t *data, size_t size) {
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

    // Write the fuzzing data to the temporary file
    fwrite(data, 1, size, file);
    fclose(file);

    // Open the TIFF file
    TIFF *tiff = TIFFOpen(tmpl, "r");
    if (!tiff) {
        remove(tmpl);
        return 0;
    }

    // Prepare parameters for TIFFReadRGBATileExt
    uint32_t x = 0;
    uint32_t y = 0;
    uint32_t *raster = (uint32_t *)malloc(sizeof(uint32_t) * TIFFTileSize(tiff));
    if (!raster) {
        TIFFClose(tiff);
        remove(tmpl);
        return 0;
    }
    int stopOnError = 1;

    // Call the function-under-test
    TIFFReadRGBATileExt(tiff, x, y, raster, stopOnError);

    // Clean up
    free(raster);
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

    LLVMFuzzerTestOneInput_183(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
