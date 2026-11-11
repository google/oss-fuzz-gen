#include <cstddef>
#include <cstdint>
#include <cstring>

extern "C" {
    #include "cbor.h"  // Assuming the cbor_encode_uint function is declared in this header
}

extern "C" int LLVMFuzzerTestOneInput_129(const uint8_t *data, size_t size) {
    // Ensure there's enough data to read a uint64_t value
    if (size < sizeof(uint64_t)) {
        return 0;
    }

    // Extract a uint64_t value from the input data
    uint64_t uint_value;
    memcpy(&uint_value, data, sizeof(uint64_t));

    // Prepare a buffer for encoding
    size_t buffer_size = 256; // Arbitrary buffer size for encoded data
    unsigned char buffer[buffer_size];

    // Call the function-under-test
    size_t encoded_size = cbor_encode_uint(uint_value, buffer, buffer_size);

    // Use the encoded_size to prevent unused variable warning
    (void)encoded_size;

    return 0;
}