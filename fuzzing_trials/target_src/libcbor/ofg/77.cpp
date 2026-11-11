#include <cstddef>
#include <cstdint>
#include <cstring>
#include <cstdio>

extern "C" {
    // Declaration of the function-under-test
    size_t cbor_encode_uint16(uint16_t value, unsigned char *buffer, size_t buffer_size);
}

extern "C" int LLVMFuzzerTestOneInput_77(const uint8_t *data, size_t size) {
    // Check if the input size is sufficient to extract a uint16_t value
    if (size < sizeof(uint16_t)) {
        return 0;
    }

    // Extract a uint16_t value from the input data
    uint16_t value;
    memcpy(&value, data, sizeof(uint16_t));

    // Prepare a buffer for encoding
    unsigned char buffer[32]; // Arbitrary buffer size for encoding
    size_t buffer_size = sizeof(buffer);

    // Call the function-under-test
    cbor_encode_uint16(value, buffer, buffer_size);

    return 0;
}