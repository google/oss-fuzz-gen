#include <cstdint>
#include <cstddef>
#include <cstring>
#include <iostream>  // For debugging output

extern "C" {
    #include "cbor.h"  // Assuming cbor.h is the header file where cbor_encode_uint64 is declared.
}

extern "C" int LLVMFuzzerTestOneInput_42(const uint8_t *data, size_t size) {
    if (size < sizeof(uint64_t)) {
        return 0;  // Not enough data to form a uint64_t
    }

    // Extract a uint64_t from the input data
    uint64_t value;
    memcpy(&value, data, sizeof(uint64_t));

    // Prepare a buffer for encoding
    unsigned char buffer[32];  // Arbitrary buffer size
    size_t buffer_size = sizeof(buffer);

    // Call the function-under-test and check the result
    size_t result = cbor_encode_uint64(value, buffer, buffer_size);

    // For debugging: print the result and buffer content
    std::cout << "Encoded result size: " << result << std::endl;
    std::cout << "Buffer content: ";
    for (size_t i = 0; i < result; ++i) {
        std::cout << std::hex << static_cast<int>(buffer[i]) << " ";
    }
    std::cout << std::dec << std::endl;

    return 0;
}