#include <cstdint>
#include <cstddef>
#include <tiffio.h>

extern "C" int LLVMFuzzerTestOneInput_213(const uint8_t *data, size_t size) {
    // Ensure that the size is a multiple of the size of uint16_t
    if (size < sizeof(uint16_t) || size % sizeof(uint16_t) != 0) {
        return 0;
    }

    // Calculate the number of uint16_t elements
    tmsize_t num_elements = size / sizeof(uint16_t);

    // Create a buffer to hold the uint16_t elements
    uint16_t *shortArray = new uint16_t[num_elements];

    // Copy data into the uint16_t array
    for (tmsize_t i = 0; i < num_elements; ++i) {
        shortArray[i] = static_cast<uint16_t>(data[i * sizeof(uint16_t)] | (data[i * sizeof(uint16_t) + 1] << 8));
    }

    // Call the function-under-test
    TIFFSwabArrayOfShort(shortArray, num_elements);

    // Clean up
    delete[] shortArray;

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

    LLVMFuzzerTestOneInput_213(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
