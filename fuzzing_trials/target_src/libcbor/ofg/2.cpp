#include <cstddef>
#include <cstdint>
#include <cstring>

extern "C" {
    #include "cbor.h"  // Assuming this is the header where cbor_encode_negint64 is declared
}

extern "C" int LLVMFuzzerTestOneInput_2(const uint8_t *data, size_t size) {
    // Ensure there's enough data to extract a uint64_t value
    if (size < sizeof(uint64_t)) {
        return 0;
    }

    // Extract a uint64_t value from the input data
    uint64_t value;
    std::memcpy(&value, data, sizeof(uint64_t));

    // Prepare a buffer to encode the negative integer
    unsigned char buffer[256];  // Arbitrary buffer size
    size_t buffer_size = sizeof(buffer);

    // Ensure the value is interpreted as a negative integer
    if (value == 0) {
        value = 1;  // Avoid zero as it might not be a valid negative integer representation
    }

    // Call the function-under-test
    // Convert the value to a negative integer representation
    cbor_encode_negint64(value - 1, buffer, buffer_size);

    return 0;
}