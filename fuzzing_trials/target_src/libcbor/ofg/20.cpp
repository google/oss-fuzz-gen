#include <cstddef>
#include <cstdint>
#include <cstring> // For memcpy

// Assuming the function-under-test is declared in an external C library
extern "C" {
    size_t cbor_encode_undef(unsigned char *buffer, size_t buffer_size);
}

extern "C" int LLVMFuzzerTestOneInput_20(const uint8_t *data, size_t size) {
    // Check if the input size is zero, return immediately as there's nothing to test
    if (size == 0) {
        return 0;
    }

    // Allocate a buffer that is non-null and has a reasonable size
    size_t buffer_size = 256; // Arbitrary non-zero size for the buffer
    unsigned char buffer[buffer_size];

    // Copy data into the buffer, up to the buffer's size
    size_t copy_size = (size < buffer_size) ? size : buffer_size;
    memcpy(buffer, data, copy_size);

    // Fill the rest of the buffer with a specific pattern if the input is smaller than the buffer
    if (size < buffer_size) {
        memset(buffer + size, 0xFF, buffer_size - size);
    }

    // Call the function-under-test with the buffer and its size
    cbor_encode_undef(buffer, buffer_size);

    return 0;
}