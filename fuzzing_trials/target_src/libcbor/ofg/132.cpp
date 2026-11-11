#include <cstdint>
#include <cstddef>
#include <cstring>

// Assume the function is defined in a C library
extern "C" {
    size_t cbor_encode_negint16(uint16_t value, unsigned char *buffer, size_t buffer_size);
}

extern "C" int LLVMFuzzerTestOneInput_132(const uint8_t *data, size_t size) {
    // Ensure the buffer is large enough to hold the encoded data
    const size_t buffer_size = 10;
    unsigned char buffer[buffer_size];

    // Initialize a uint16_t value from the input data
    uint16_t value = 0;
    if (size >= sizeof(uint16_t)) {
        // Copy the first two bytes to form a uint16_t value
        std::memcpy(&value, data, sizeof(uint16_t));
    }

    // Call the function-under-test
    cbor_encode_negint16(value, buffer, buffer_size);

    return 0;
}