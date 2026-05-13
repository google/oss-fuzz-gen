#include <cstddef>
#include <cstdint>
#include <cstring>

// Assume the function-under-test is declared in an external C library
extern "C" {
    size_t cbor_encode_indef_string_start(unsigned char *buffer, size_t buffer_size);
}

extern "C" int LLVMFuzzerTestOneInput_136(const uint8_t *data, size_t size) {
    // Allocate a buffer with a fixed size for fuzzing
    unsigned char buffer[256];
    size_t buffer_size = sizeof(buffer);

    // Ensure the buffer is not empty and data is not null
    if (size > 0 && data != nullptr) {
        // Copy the fuzzing data into the buffer, limiting to the buffer size
        size_t copy_size = size < buffer_size ? size : buffer_size;
        memcpy(buffer, data, copy_size);

        // Call the function-under-test with the prepared buffer and size
        // Use a loop to vary buffer_size to explore different code paths
        for (size_t i = 1; i <= copy_size; ++i) {
            // Ensure the buffer is null-terminated if the function expects a string
            if (i < buffer_size) {
                buffer[i] = '\0';
            }
            cbor_encode_indef_string_start(buffer, i);
        }
    }

    return 0;
}