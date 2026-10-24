#include <cstdint>
#include <cstddef>
#include <cstring>

extern "C" {
    // Assuming the function is defined in a C library
    size_t cbor_encode_uint32(uint32_t value, unsigned char *buffer, size_t buffer_size);
}

extern "C" int LLVMFuzzerTestOneInput_176(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient to extract a uint32_t value
    if (size < sizeof(uint32_t)) {
        return 0;
    }

    // Extract a uint32_t value from the input data
    uint32_t value;
    memcpy(&value, data, sizeof(uint32_t));

    // Prepare a buffer to hold the encoded result
    unsigned char buffer[128];  // Arbitrary buffer size for encoding
    size_t buffer_size = sizeof(buffer);

    // Call the function-under-test and check the result
    size_t encoded_size = cbor_encode_uint32(value, buffer, buffer_size);

    // Check if the encoding was successful and the encoded size is valid
    if (encoded_size > 0 && encoded_size <= buffer_size) {
        // Optionally, perform additional checks or operations on the encoded data
    }

    return 0;
}