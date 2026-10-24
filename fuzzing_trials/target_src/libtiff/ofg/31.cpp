#include <cstdint>
#include <cstdlib>
#include <tiffio.h>  // Include the TIFF library header

extern "C" int LLVMFuzzerTestOneInput_31(const uint8_t *data, size_t size) {
    // Initialize TIFF structure
    TIFF *tiff = TIFFOpen("/tmp/fuzzfileXXXXXX", "w+");
    if (tiff == NULL) {
        return 0;  // Return if TIFF structure couldn't be initialized
    }

    // Ensure there is enough data to extract an integer for mode
    if (size < sizeof(int)) {
        TIFFClose(tiff);
        return 0;
    }

    // Extract an integer value for mode from the input data
    int mode = *reinterpret_cast<const int*>(data);

    // Call the function-under-test
    TIFFSetMode(tiff, mode);

    // Clean up
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

    LLVMFuzzerTestOneInput_31(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
