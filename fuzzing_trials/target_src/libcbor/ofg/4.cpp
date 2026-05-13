#include <cstdint>
#include <cstddef>
#include <cstring>

extern "C" {
    #include "cbor.h"  // Ensure to include the appropriate header for the function-under-test
}

extern "C" int LLVMFuzzerTestOneInput_4(const uint8_t *data, size_t size) {
    // Check if the input size is sufficient for the parameters
    if (size < 1) {
        return 0;
    }

    // Initialize the parameters for the function-under-test
    uint8_t negint_value = data[0];  // Use the first byte of data for the uint8_t parameter

    // Allocate a buffer for the encoded output
    size_t buffer_size = 10;  // Arbitrary buffer size for testing
    unsigned char buffer[buffer_size];
    memset(buffer, 0, buffer_size);  // Initialize buffer to zero

    // Call the function-under-test
    size_t encoded_size = cbor_encode_negint8(negint_value, buffer, buffer_size);

    // Use encoded_size to prevent compiler optimizations that remove the function call
    (void)encoded_size;

    return 0;
}