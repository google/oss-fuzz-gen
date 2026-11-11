#include <cstdint>
#include <cstddef>
#include <tiffio.h>

extern "C" int LLVMFuzzerTestOneInput_38(const uint8_t *data, size_t size) {
    // Ensure the size is a multiple of 4 since we are dealing with uint32_t
    if (size < 4 || size % 4 != 0) {
        return 0;
    }

    // Calculate the number of uint32_t elements
    tmsize_t num_elements = static_cast<tmsize_t>(size / 4);

    // Allocate memory for the array of uint32_t
    uint32_t *longArray = new uint32_t[num_elements];

    // Copy data into longArray
    for (tmsize_t i = 0; i < num_elements; ++i) {
        longArray[i] = static_cast<uint32_t>(data[i * 4]) |
                       (static_cast<uint32_t>(data[i * 4 + 1]) << 8) |
                       (static_cast<uint32_t>(data[i * 4 + 2]) << 16) |
                       (static_cast<uint32_t>(data[i * 4 + 3]) << 24);
    }

    // Call the function-under-test
    TIFFSwabArrayOfLong(longArray, num_elements);

    // Clean up
    delete[] longArray;

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

    LLVMFuzzerTestOneInput_38(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
