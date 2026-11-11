#include <cstdint>
#include <cstdlib>
#include <tiffio.h>

extern "C" int LLVMFuzzerTestOneInput_192(const uint8_t *data, size_t size) {
    // Ensure size is sufficient for a uint32_t value
    if (size < sizeof(uint32_t)) {
        return 0;
    }

    // Create a TIFF structure using TIFFClientOpen
    TIFF *tiff = TIFFClientOpen("MemTIFF", "r", nullptr,
                                nullptr, nullptr, nullptr, nullptr,
                                nullptr, nullptr, nullptr);

    if (tiff == nullptr) {
        return 0;
    }

    // Extract a uint32_t value from the data
    uint32_t parameter = *(reinterpret_cast<const uint32_t*>(data));

    // Call the function-under-test
    uint32_t result = TIFFDefaultStripSize(tiff, parameter);

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

    LLVMFuzzerTestOneInput_192(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
