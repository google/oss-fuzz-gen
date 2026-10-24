#include <cstdint>
#include <cstddef>
#include <cstring>

extern "C" {
    // Assuming the function is defined in an external C library
    size_t cbor_encode_uint8(uint8_t value, unsigned char *buffer, size_t buffer_size);
}

extern "C" int LLVMFuzzerTestOneInput_50(const uint8_t *data, size_t size) {
    // Ensure there's at least 1 byte for the uint8_t value
    if (size < 1) {
        return 0;
    }

    uint8_t value = data[0]; // Use the first byte of data as the uint8_t value

    // Allocate a buffer for encoding
    size_t buffer_size = 10; // Arbitrary buffer size for encoding
    unsigned char buffer[buffer_size];
    memset(buffer, 0, buffer_size);

    // Call the function-under-test
    cbor_encode_uint8(value, buffer, buffer_size);

    return 0;
}