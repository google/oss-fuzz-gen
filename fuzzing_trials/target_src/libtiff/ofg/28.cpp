#include <cstdint>
#include <cstddef>
#include <tiffio.h>

extern "C" int LLVMFuzzerTestOneInput_28(const uint8_t *data, size_t size) {
    // Ensure that the data size is sufficient to extract an integer
    if (size < sizeof(uint8_t)) {
        return 0;
    }

    // Iterate over the input data to test the function with a range of values
    for (size_t i = 0; i < size; ++i) {
        // Extract a uint8_t value from the data
        uint8_t input_value = data[i];

        // Call the function-under-test
        const unsigned char *result = TIFFGetBitRevTable(input_value);

        // Use the result to avoid compiler optimizations that might remove the call
        if (result) {
            // Iterate over the result to ensure the entire table is utilized
            for (size_t j = 0; j < 256; ++j) {
                volatile unsigned char value = result[j];
                (void)value; // Suppress unused variable warning
            }
        }
    }

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

    LLVMFuzzerTestOneInput_28(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
