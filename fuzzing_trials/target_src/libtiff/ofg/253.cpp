#include <tiffio.h>
#include <cstdint>
#include <cstdlib>
#include <cstdio>
#include <unistd.h> // For unlink and close
#include <cstring>  // For memcpy

extern "C" int LLVMFuzzerTestOneInput_253(const uint8_t *data, size_t size) {
    TIFF *tiff = NULL;
    void *scanline = NULL;
    uint32_t row = 0;
    uint16_t sample = 0;
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(tmpl);

    if (fd == -1) {
        return 0;
    }

    // Use fdopen to associate a FILE stream with the file descriptor
    FILE *file = fdopen(fd, "wb+");
    if (!file) {
        close(fd);
        return 0;
    }

    // Write the fuzz data to the file
    if (fwrite(data, 1, size, file) != size) {
        fclose(file);
        return 0;
    }

    // Rewind the file to the beginning for reading
    rewind(file);

    // Open the TIFF file
    tiff = TIFFOpen(tmpl, "r+");
    if (!tiff) {
        fclose(file);
        return 0;
    }

    // Allocate memory for the scanline
    scanline = malloc(size);
    if (!scanline) {
        TIFFClose(tiff);
        fclose(file);
        return 0;
    }

    // Initialize the scanline with some data
    memcpy(scanline, data, size);

    // Fuzz the TIFFWriteScanline function
    TIFFWriteScanline(tiff, scanline, row, sample);

    // Clean up
    free(scanline);
    TIFFClose(tiff);
    fclose(file);
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

    LLVMFuzzerTestOneInput_253(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
