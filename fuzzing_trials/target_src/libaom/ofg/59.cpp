#include <cstdint>
#include <cstddef>
#include <cstring>
#include <aom/aom_integer.h> // Assuming this is where aom_uleb_encode is declared

extern "C" {
    // Include the function-under-test declaration
    int aom_uleb_encode(uint64_t value, size_t available, uint8_t *coded, size_t *coded_size);
}

extern "C" int LLVMFuzzerTestOneInput_59(const uint8_t *data, size_t size) {
    // Declare and initialize the variables needed for aom_uleb_encode
    uint64_t value = 0;
    size_t available = 0;
    uint8_t coded[10]; // Assuming a maximum of 10 bytes for ULEB encoding
    size_t coded_size = 0;

    // Ensure size is sufficient to extract value and available
    if (size < sizeof(uint64_t) + sizeof(size_t)) {
        return 0;
    }

    // Extract value and available from data
    memcpy(&value, data, sizeof(uint64_t));
    memcpy(&available, data + sizeof(uint64_t), sizeof(size_t));

    // Ensure available does not exceed the coded buffer size
    available = available % sizeof(coded);

    // Call the function-under-test
    aom_uleb_encode(value, available, coded, &coded_size);

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

    LLVMFuzzerTestOneInput_59(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
