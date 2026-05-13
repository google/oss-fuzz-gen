#include <cstdint>
#include <cstddef>
#include <tiffio.h>

extern "C" int LLVMFuzzerTestOneInput_212(const uint8_t *data, size_t size) {
    // Ensure the size is a multiple of 2 for uint16_t array
    if (size < sizeof(uint16_t) || size % sizeof(uint16_t) != 0) {
        return 0;
    }

    // Calculate the number of uint16_t elements
    tmsize_t num_elements = static_cast<tmsize_t>(size / sizeof(uint16_t));

    // Allocate memory for the uint16_t array
    uint16_t *short_array = new uint16_t[num_elements];

    // Copy data into the uint16_t array
    for (tmsize_t i = 0; i < num_elements; ++i) {
        short_array[i] = static_cast<uint16_t>(data[i * 2] | (data[i * 2 + 1] << 8));
    }

    // Call the function-under-test
    TIFFSwabArrayOfShort(short_array, num_elements);

    // Clean up
    delete[] short_array;

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

    LLVMFuzzerTestOneInput_212(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
