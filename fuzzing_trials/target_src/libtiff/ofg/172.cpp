#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h> // Include the unistd.h header for the close function

extern "C" {
    #include <tiffio.h> // Wrap the inclusion of the C library in extern "C"
}

extern "C" int LLVMFuzzerTestOneInput_172(const uint8_t *data, size_t size) {
    // Create a temporary file to store the TIFF data
    char tmpl[] = "/tmp/fuzz_tiff_XXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        return 0;
    }
    FILE *file = fdopen(fd, "wb");
    if (!file) {
        close(fd);
        return 0;
    }

    // Write the fuzz data to the temporary file
    fwrite(data, 1, size, file);
    fclose(file);

    // Open the temporary file as a TIFF image
    TIFF *tiff = TIFFOpen(tmpl, "r");
    if (!tiff) {
        remove(tmpl);
        return 0;
    }

    // Allocate a buffer for the tile data
    tmsize_t tileSize = TIFFTileSize(tiff);
    void *tileBuffer = malloc(tileSize);
    if (!tileBuffer) {
        TIFFClose(tiff);
        remove(tmpl);
        return 0;
    }

    // Call the function-under-test with various parameters
    uint32_t x = 0; // Starting x-coordinate
    uint32_t y = 0; // Starting y-coordinate
    uint32_t z = 0; // Starting z-coordinate (for 3D TIFFs)
    uint16_t sample = 0; // Sample index

    // Attempt to read a tile
    TIFFReadTile(tiff, tileBuffer, x, y, z, sample);

    // Clean up
    free(tileBuffer);
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

    LLVMFuzzerTestOneInput_172(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
