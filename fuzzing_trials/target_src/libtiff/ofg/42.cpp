#include <cstdint>
#include <cstdlib>
#include <tiffio.h>

extern "C" int LLVMFuzzerTestOneInput_42(const uint8_t *data, size_t size) {
    // Initialize TIFF structure
    TIFF *tiff = TIFFOpen("/tmp/fuzzfile.tiff", "r");
    if (tiff == nullptr) {
        return 0;
    }

    // Ensure data is not NULL and has a size
    if (data == nullptr || size == 0) {
        TIFFClose(tiff);
        return 0;
    }

    // Allocate a buffer for the tile data
    tmsize_t bufferSize = static_cast<tmsize_t>(size);
    void *buffer = malloc(bufferSize);
    if (buffer == nullptr) {
        TIFFClose(tiff);
        return 0;
    }

    // Use a fixed tile index for testing
    uint32_t tileIndex = 0;

    // Call the function-under-test
    tmsize_t bytesRead = TIFFReadRawTile(tiff, tileIndex, buffer, bufferSize);

    // Clean up
    free(buffer);
    TIFFClose(tiff);

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

    LLVMFuzzerTestOneInput_42(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
