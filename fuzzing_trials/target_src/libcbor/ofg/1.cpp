#include <cstdint>
#include <cstddef>
#include <cstring>

extern "C" {
    #include "cbor.h"  // Assuming the function is defined in a library that provides this header
}

extern "C" int LLVMFuzzerTestOneInput_1(const uint8_t *data, size_t size) {
    // Ensure the size is sufficient to extract a uint64_t value
    if (size < sizeof(uint64_t)) {
        return 0;
    }

    // Extract a uint64_t value from the input data
    uint64_t value;
    memcpy(&value, data, sizeof(uint64_t));

    // Define a buffer to hold the encoded result
    unsigned char buffer[128];  // Assume a reasonable size for the buffer

    // Call the function-under-test
    size_t result = cbor_encode_negint64(value, buffer, sizeof(buffer));

    // Check if the function call was successful by verifying the result
    if (result > 0 && result <= sizeof(buffer)) {
        // Use the buffer in some way to ensure it's not optimized away
        for (size_t i = 0; i < result; ++i) {
            // Perform a simple operation on the buffer
            buffer[i] ^= 0xFF;
        }
    } else {
        // Handle the case where encoding fails or the result is invalid
        // This can help ensure that the function is being tested effectively
        return 1;
    }

    return 0;
}