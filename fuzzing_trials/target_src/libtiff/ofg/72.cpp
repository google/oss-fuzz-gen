#include <stdint.h>
#include <stddef.h>

extern "C" {
    #include <tiffio.h>
}

extern "C" int LLVMFuzzerTestOneInput_72(const uint8_t *data, size_t size) {
    // Ensure that the size is sufficient for a minimal valid TIFF operation
    if (size < sizeof(uint32_t)) {
        return 0;
    }

    // Create a dummy TIFF structure
    TIFF *tiff = TIFFClientOpen("MemTIFF", "r", (thandle_t)data,
                                [](thandle_t, void*, tmsize_t) -> tmsize_t { return 0; },
                                [](thandle_t, void*, tmsize_t) -> tmsize_t { return 0; },
                                [](thandle_t, toff_t, int) -> toff_t { return 0; },
                                [](thandle_t) -> int { return 0; },
                                [](thandle_t) -> toff_t { return 0; },
                                [](thandle_t, void**, toff_t*) -> int { return 0; }, // TIFFMapFileProc
                                [](thandle_t, void*, toff_t) -> void { }); // TIFFUnmapFileProc

    if (tiff == nullptr) {
        return 0;
    }

    // Use a fixed uint32_t value for testing
    uint32_t sampleValue = 1;

    // Call the function-under-test
    tmsize_t tileSize = TIFFVTileSize(tiff, sampleValue);

    // Use tileSize in some way to prevent compiler optimizations
    (void)tileSize;

    // Close the TIFF structure
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

    LLVMFuzzerTestOneInput_72(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
