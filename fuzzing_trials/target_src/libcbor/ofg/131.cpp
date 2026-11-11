#include <cstdint>
#include <cstddef>
#include <cstring>

extern "C" {
    // Assume the function is declared in some header file
    size_t cbor_encode_negint16(uint16_t value, unsigned char *buffer, size_t buffer_size);
}

extern "C" int LLVMFuzzerTestOneInput_131(const uint8_t *data, size_t size) {
    // Ensure the size is at least 2 bytes to extract a uint16_t value
    if (size < 2) {
        return 0;
    }

    // Extract a uint16_t value from the input data
    uint16_t value;
    memcpy(&value, data, sizeof(uint16_t));

    // Create a buffer to store the encoded result
    unsigned char buffer[10]; // Arbitrary buffer size for testing
    size_t buffer_size = sizeof(buffer);

    // Call the function-under-test
    cbor_encode_negint16(value, buffer, buffer_size);

    return 0;
}