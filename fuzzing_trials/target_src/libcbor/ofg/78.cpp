#include <cstddef>
#include <cstdint>
#include <cstring>

// Assuming the function is defined elsewhere
extern "C" size_t cbor_encode_uint16(uint16_t value, unsigned char *buffer, size_t buffer_size);

extern "C" int LLVMFuzzerTestOneInput_78(const uint8_t *data, size_t size) {
    // Ensure the size is sufficient to extract a uint16_t value
    if (size < sizeof(uint16_t)) {
        return 0;
    }

    // Extract a uint16_t value from the input data
    uint16_t value;
    std::memcpy(&value, data, sizeof(uint16_t));

    // Allocate a buffer to hold the encoded data
    unsigned char buffer[256]; // Arbitrary size for the buffer
    size_t buffer_size = sizeof(buffer);

    // Call the function-under-test
    cbor_encode_uint16(value, buffer, buffer_size);

    return 0;
}