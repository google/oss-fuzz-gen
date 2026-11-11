#include <stdint.h>
#include <stddef.h>
#include <tiffio.h>

extern "C" int LLVMFuzzerTestOneInput_206(const uint8_t *data, size_t size) {
    // Initialize TIFF structure
    TIFF *tiff = TIFFOpen("/tmp/fuzzfileXXXXXX", "w");
    if (tiff == NULL) {
        return 0; // Return if TIFFOpen fails
    }

    // Ensure we have enough data to create a uint32_t value
    if (size < sizeof(uint32_t)) {
        TIFFClose(tiff);
        return 0;
    }

    // Extract a uint32_t value from the data
    uint32_t stripIndex = *(reinterpret_cast<const uint32_t*>(data));

    // Call the function-under-test
    tmsize_t result = TIFFRawStripSize(tiff, stripIndex);

    // Close the TIFF file
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

    LLVMFuzzerTestOneInput_206(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
