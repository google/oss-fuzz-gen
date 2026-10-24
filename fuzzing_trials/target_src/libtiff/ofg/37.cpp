#include <cstdint>
#include <cstddef>
#include <tiffio.h>

extern "C" int LLVMFuzzerTestOneInput_37(const uint8_t *data, size_t size) {
    // Ensure the data size is a multiple of sizeof(uint32_t) to avoid incomplete uint32_t values
    if (size < sizeof(uint32_t)) {
        return 0;
    }

    // Calculate the number of uint32_t elements
    tmsize_t numElements = size / sizeof(uint32_t);

    // Allocate memory for the uint32_t array
    uint32_t *array = new uint32_t[numElements];

    // Copy data into the uint32_t array
    for (tmsize_t i = 0; i < numElements; ++i) {
        array[i] = ((uint32_t)data[i * 4] << 24) |
                   ((uint32_t)data[i * 4 + 1] << 16) |
                   ((uint32_t)data[i * 4 + 2] << 8) |
                   ((uint32_t)data[i * 4 + 3]);
    }

    // Call the function-under-test
    TIFFSwabArrayOfLong(array, numElements);

    // Clean up
    delete[] array;

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

    LLVMFuzzerTestOneInput_37(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
