#include <cstdint>
#include <cstddef>
#include <tiffio.h>

extern "C" int LLVMFuzzerTestOneInput_181(const uint8_t *data, size_t size) {
    // Ensure there's enough data to form at least one uint64_t element
    if (size < sizeof(uint64_t)) {
        return 0;
    }

    // Calculate the number of uint64_t elements
    tmsize_t num_elements = size / sizeof(uint64_t);

    // Allocate memory for the array of uint64_t
    uint64_t *array = new uint64_t[num_elements];

    // Copy the input data into the array
    for (tmsize_t i = 0; i < num_elements; ++i) {
        array[i] = ((uint64_t)data[i * 8 + 0] << 56) |
                   ((uint64_t)data[i * 8 + 1] << 48) |
                   ((uint64_t)data[i * 8 + 2] << 40) |
                   ((uint64_t)data[i * 8 + 3] << 32) |
                   ((uint64_t)data[i * 8 + 4] << 24) |
                   ((uint64_t)data[i * 8 + 5] << 16) |
                   ((uint64_t)data[i * 8 + 6] << 8) |
                   ((uint64_t)data[i * 8 + 7]);
    }

    // Call the function-under-test
    TIFFSwabArrayOfLong8(array, num_elements);

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

    LLVMFuzzerTestOneInput_181(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
