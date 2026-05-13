#include <string.h>
#include <sys/stat.h>
#include <cstdint>
#include <cstddef>
#include <cstring>
#include "/src/aom/aom/aom_integer.h" // Assuming this is the correct header for aom_uleb_encode

extern "C" {
    int aom_uleb_encode(uint64_t value, size_t available, uint8_t *buffer, size_t *encoded_size);
}

extern "C" int LLVMFuzzerTestOneInput_12(const uint8_t *data, size_t size) {
    // Ensure that the input size is sufficient to extract meaningful parameters
    if (size < sizeof(uint64_t) + sizeof(size_t)) {
        return 0;
    }

    // Extract parameters from the input data
    uint64_t value;
    size_t available;

    // Copy data into variables
    memcpy(&value, data, sizeof(uint64_t));
    memcpy(&available, data + sizeof(uint64_t), sizeof(size_t));

    // Limit the available size to prevent excessive memory allocation
    const size_t max_buffer_size = 1024; // Define a reasonable maximum buffer size
    if (available > max_buffer_size) {
        return 0; // Early exit if the available size is too large
    }

    // Allocate buffer for encoding
    uint8_t *buffer = new uint8_t[available];

    // Prepare a variable to hold the encoded size
    size_t encoded_size = 0;

    // Call the function under test
    aom_uleb_encode(value, available, buffer, &encoded_size);

    // Clean up
    delete[] buffer;

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

    LLVMFuzzerTestOneInput_12(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
