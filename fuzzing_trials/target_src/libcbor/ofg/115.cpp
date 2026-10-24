#include <cstddef>
#include <cstdint>
#include <cstring>
#include <iostream>

extern "C" {
    #include "cbor.h" // Assuming cbor.h contains the declaration for cbor_encode_negint
}

// Function signature to be fuzzed
extern "C" size_t cbor_encode_negint(uint64_t value, unsigned char *buffer, size_t buffer_size);

extern "C" int LLVMFuzzerTestOneInput_115(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient for our needs
    if (size < sizeof(uint64_t) + 1) {
        return 0;
    }

    // Extract a uint64_t value from the input data
    uint64_t negint_value;
    memcpy(&negint_value, data, sizeof(uint64_t));

    // Prepare a buffer for encoding
    unsigned char encode_buffer[128]; // Arbitrary size for encoding buffer
    size_t encode_buffer_size = sizeof(encode_buffer);

    // Call the function-under-test
    cbor_encode_negint(negint_value, encode_buffer, encode_buffer_size);

    return 0;
}