#include <cstdint>
#include <cstdlib>
#include <cstdio>
#include <unistd.h>
#include <fcntl.h>
#include <tiffio.h>

extern "C" int LLVMFuzzerTestOneInput_214(const uint8_t *data, size_t size) {
    // Create a temporary file to store the input data
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        return 0;
    }

    // Write the input data to the temporary file
    if (write(fd, data, size) != (ssize_t)size) {
        close(fd);
        unlink(tmpl);
        return 0;
    }
    close(fd);

    // Open the TIFF file
    TIFF *tiff = TIFFOpen(tmpl, "r");
    if (!tiff) {
        unlink(tmpl);
        return 0;
    }

    // Prepare parameters for TIFFReadRGBAImage
    uint32_t width = 1;  // Minimal non-zero width
    uint32_t height = 1; // Minimal non-zero height
    uint32_t *raster = (uint32_t *)malloc(width * height * sizeof(uint32_t));
    if (!raster) {
        TIFFClose(tiff);
        unlink(tmpl);
        return 0;
    }
    int stopOnError = 1; // Stop on error

    // Call the function-under-test
    TIFFReadRGBAImage(tiff, width, height, raster, stopOnError);

    // Clean up
    free(raster);
    TIFFClose(tiff);
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

    LLVMFuzzerTestOneInput_214(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
