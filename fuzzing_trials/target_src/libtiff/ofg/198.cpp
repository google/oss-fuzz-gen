#include <cstdint>
#include <cstdio>
#include <cstdlib>

extern "C" {
    #include <tiffio.h>
}

extern "C" int LLVMFuzzerTestOneInput_198(const uint8_t *data, size_t size) {
    if (size < sizeof(uint32_t) * 3 + sizeof(uint16_t)) {
        return 0;
    }

    // Initialize TIFF structure
    TIFF *tiff = TIFFClientOpen("MemTIFF", "r", (thandle_t)data,
                                nullptr, nullptr, nullptr, nullptr,
                                nullptr, nullptr, nullptr);

    if (tiff == nullptr) {
        return 0;
    }

    // Extract values from data to use as parameters
    uint32_t x = *(reinterpret_cast<const uint32_t *>(data));
    uint32_t y = *(reinterpret_cast<const uint32_t *>(data + sizeof(uint32_t)));
    uint32_t z = *(reinterpret_cast<const uint32_t *>(data + 2 * sizeof(uint32_t)));
    uint16_t s = *(reinterpret_cast<const uint16_t *>(data + 3 * sizeof(uint32_t)));

    // Call the function-under-test
    uint32_t tile = TIFFComputeTile(tiff, x, y, z, s);

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

    LLVMFuzzerTestOneInput_198(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
