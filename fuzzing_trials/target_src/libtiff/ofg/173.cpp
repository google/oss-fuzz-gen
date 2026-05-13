#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <unistd.h>  // Include for close() and unlink()

extern "C" {
    #include <tiffio.h>
}

extern "C" int LLVMFuzzerTestOneInput_173(const uint8_t *data, size_t size) {
    // Create a temporary file to write the fuzz data
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

    // Open the temporary file with libtiff
    TIFF *tiff = TIFFOpen(tmpl, "r");
    if (!tiff) {
        unlink(tmpl);  // Use unlink() instead of remove() for consistency with close()
        return 0;
    }

    // Allocate a buffer for the tile data
    tmsize_t tileSize = TIFFTileSize(tiff);
    if (tileSize <= 0) {
        TIFFClose(tiff);
        unlink(tmpl);
        return 0;
    }
    void *tileBuffer = malloc(tileSize);
    if (!tileBuffer) {
        TIFFClose(tiff);
        unlink(tmpl);
        return 0;
    }

    // Prepare parameters for the TIFFReadTile function
    uint32_t x = 0;
    uint32_t y = 0;
    uint32_t z = 0;
    uint16_t sample = 0;

    // Call the function-under-test
    TIFFReadTile(tiff, tileBuffer, x, y, z, sample);

    // Clean up
    free(tileBuffer);
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

    LLVMFuzzerTestOneInput_173(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
