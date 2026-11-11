#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <unistd.h> // Include this header for the 'close' function

extern "C" {
    #include <tiffio.h>
}

extern "C" int LLVMFuzzerTestOneInput_217(const uint8_t *data, size_t size) {
    if (size < sizeof(uint32_t) * 2 + sizeof(int) * 2) {
        return 0; // Not enough data to extract necessary parameters
    }

    // Extract width and height from the input data
    uint32_t width = *(reinterpret_cast<const uint32_t *>(data));
    uint32_t height = *(reinterpret_cast<const uint32_t *>(data + sizeof(uint32_t)));

    // Extract orientation and stopOnError from the input data
    int orientation = *(reinterpret_cast<const int *>(data + sizeof(uint32_t) * 2));
    int stopOnError = *(reinterpret_cast<const int *>(data + sizeof(uint32_t) * 2 + sizeof(int)));

    // Ensure width and height are non-zero to avoid invalid memory allocations
    if (width == 0 || height == 0) {
        return 0;
    }

    // Create a temporary TIFF file
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
    TIFF *tiff = TIFFOpen(tmpl, "r");
    if (!tiff) {
        remove(tmpl);
        return 0;
    }

    // Allocate memory for raster
    uint32_t *raster = (uint32_t *)_TIFFmalloc(width * height * sizeof(uint32_t));
    if (!raster) {
        TIFFClose(tiff);
        remove(tmpl);
        return 0;
    }

    // Call the function-under-test
    TIFFReadRGBAImageOriented(tiff, width, height, raster, orientation, stopOnError);

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

    LLVMFuzzerTestOneInput_217(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
