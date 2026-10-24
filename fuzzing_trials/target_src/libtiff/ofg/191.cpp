#include <cstdint>
#include <cstring> // Include for memcpy

extern "C" {
    #include <tiffio.h>
}

extern "C" int LLVMFuzzerTestOneInput_191(const uint8_t *data, size_t size) {
    // Ensure the data is large enough to extract meaningful values
    if (size < sizeof(uint32_t) + sizeof(TIFFDataType)) {
        return 0;
    }

    // Create a TIFF structure
    TIFF *tiff = TIFFOpen("temp.tiff", "w");
    if (tiff == nullptr) {
        return 0;
    }

    // Extract a uint32_t tag from the data
    uint32_t tag;
    memcpy(&tag, data, sizeof(uint32_t));

    // Extract a TIFFDataType from the data
    TIFFDataType dataType;
    memcpy(&dataType, data + sizeof(uint32_t), sizeof(TIFFDataType));

    // Call the function-under-test
    const TIFFField *field = TIFFFindField(tiff, tag, dataType);

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

    LLVMFuzzerTestOneInput_191(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
