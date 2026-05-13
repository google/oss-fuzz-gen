#include <cstdint>
#include <tiffio.h>

extern "C" int LLVMFuzzerTestOneInput_210(const uint8_t *data, size_t size) {
    // Ensure there's enough data to work with
    if (size < sizeof(uint32_t)) {
        return 0;
    }

    // Initialize TIFF structure
    TIFF *tiff = TIFFOpen("/tmp/fuzzfile.tiff", "w");
    if (tiff == nullptr) {
        return 0;
    }

    // Extract a uint32_t value from the input data
    uint32_t strip = 0;
    if (size >= sizeof(uint32_t)) {
        strip = *(reinterpret_cast<const uint32_t*>(data));
    }

    // Call the function-under-test
    tmsize_t result = TIFFVStripSize(tiff, strip);

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

    LLVMFuzzerTestOneInput_210(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
