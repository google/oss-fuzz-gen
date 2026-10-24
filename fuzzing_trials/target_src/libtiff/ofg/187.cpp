#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <unistd.h> // Include this for the 'close' function

extern "C" {
    #include <tiffio.h>
}

extern "C" int LLVMFuzzerTestOneInput_187(const uint8_t *data, size_t size) {
    if (size < sizeof(uint32_t)) {
        return 0; // Not enough data to extract a uint32_t value
    }

    // Create a temporary TIFF file
    char tmpl[] = "/tmp/fuzzfileXXXXXX.tiff";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        return 0; // Failed to create a temporary file
    }

    // Write the fuzz data to the temporary file
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

    // Extract a uint32_t value from the data
    uint32_t someValue = *(reinterpret_cast<const uint32_t*>(data));

    // Check if the TIFF file is tiled
    if (TIFFIsTiled(tiff)) {
        // Ensure someValue is a valid tile index
        uint32_t tileWidth = 0, tileLength = 0;
        if (TIFFGetField(tiff, TIFFTAG_TILEWIDTH, &tileWidth) &&
            TIFFGetField(tiff, TIFFTAG_TILELENGTH, &tileLength) &&
            tileWidth > 0 && tileLength > 0) {
            
            uint32_t dirCount = TIFFNumberOfTiles(tiff);
            if (dirCount > 0) {
                someValue = someValue % dirCount; // Ensure someValue is within valid range

                // Call the function-under-test
                uint64_t tileSize = TIFFVTileSize64(tiff, someValue);

                // Check the tile size to ensure the function is doing something meaningful
                if (tileSize > 0) {
                    // Perform some operation with tileSize to ensure coverage
                    printf("Tile size: %llu\n", tileSize);
                }
            }
        }
    }

    // Clean up
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

    LLVMFuzzerTestOneInput_187(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
