#include <string.h>
#include <sys/stat.h>
#include <cstdint>
#include <cstddef>
#include <cstring>
#include <limits>
#include <new> // Include this header for std::nothrow

// Assuming the function is defined in an external C library
extern "C" {
    int aom_uleb_encode_fixed_size(uint64_t value, size_t fixed_size, size_t available_size, uint8_t *buffer, size_t *encoded_size);
}

extern "C" int LLVMFuzzerTestOneInput_11(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient for our needs
    if (size < sizeof(uint64_t) + 2 * sizeof(size_t)) {
        return 0;
    }

    // Extract values from the input data
    uint64_t value;
    size_t fixed_size, available_size;
    size_t encoded_size = 0;

    // Copy data into variables
    std::memcpy(&value, data, sizeof(uint64_t));
    std::memcpy(&fixed_size, data + sizeof(uint64_t), sizeof(size_t));
    std::memcpy(&available_size, data + sizeof(uint64_t) + sizeof(size_t), sizeof(size_t));

    // Limit the available_size to prevent excessive memory allocation
    const size_t max_buffer_size = 1024; // Define a reasonable maximum buffer size
    if (available_size > max_buffer_size) {
        available_size = max_buffer_size;
    }

    // Ensure buffer is not NULL and has at least one byte
    uint8_t *buffer = new (std::nothrow) uint8_t[available_size > 0 ? available_size : 1];
    if (!buffer) {
        // Handle memory allocation failure
        return 0;
    }

    // Call the function-under-test
    aom_uleb_encode_fixed_size(value, fixed_size, available_size, buffer, &encoded_size);

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

    LLVMFuzzerTestOneInput_11(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
