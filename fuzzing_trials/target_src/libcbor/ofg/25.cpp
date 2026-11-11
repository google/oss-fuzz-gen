#include <cstddef>
#include <cstdint>
#include <cstring>

extern "C" {
    #include "cbor.h"  // Assuming cbor.h contains the declaration for cbor_encode_string_start
}

extern "C" int LLVMFuzzerTestOneInput_25(const uint8_t *data, size_t size) {
    // Ensure size is at least 1 to prevent zero-length allocations
    if (size < 1) {
        return 0;
    }

    // Initialize the parameters for the function-under-test
    size_t string_length = static_cast<size_t>(data[0]); // Use the first byte as a length
    unsigned char *buffer = new unsigned char[size]; // Allocate a buffer of size 'size'
    size_t buffer_size = size;

    // Copy the data into the buffer
    std::memcpy(buffer, data, size);

    // Call the function-under-test
    cbor_encode_string_start(string_length, buffer, buffer_size);

    // Clean up
    delete[] buffer;

    return 0;
}