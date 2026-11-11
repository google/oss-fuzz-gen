#include <cstddef>
#include "cstdint"
#include <cstring>

// Assume the function-under-test is declared in an external C library.
extern "C" {
    size_t cbor_encode_uint(uint64_t value, unsigned char *buffer, size_t buffer_size);
}

extern "C" int LLVMFuzzerTestOneInput_22(const uint8_t *data, size_t size) {
    // Ensure the size is sufficient to extract a uint64_t value and provide a buffer.
    if (size < sizeof(uint64_t) + 1) {
        return 0;
    }

    // Extract a uint64_t value from the input data.
    uint64_t value;
    std::memcpy(&value, data, sizeof(uint64_t));

    // Prepare a buffer with the remaining size.
    unsigned char buffer[256];
    size_t buffer_size = sizeof(buffer);

    // Call the function-under-test with the extracted value and buffer.
    cbor_encode_uint(value, buffer, buffer_size);

    return 0;
}