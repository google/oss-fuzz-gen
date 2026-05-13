#include <cstddef>
#include "cstdint"
#include <cstring> // For memcpy

extern "C" {
    // Function signature from the provided task
    size_t cbor_encode_half(float value, unsigned char *buffer, size_t buffer_size);
}

extern "C" int LLVMFuzzerTestOneInput_25(const uint8_t *data, size_t size) {
    // Ensure the buffer is not NULL and has a reasonable size
    if (size < sizeof(float) + 1) {
        return 0;
    }

    // Create a separate buffer for the float value to avoid modifying the input data
    float value;
    std::memcpy(&value, data, sizeof(float));

    // Create a separate buffer for the rest of the data
    unsigned char *buffer = new unsigned char[size - sizeof(float)];
    std::memcpy(buffer, data + sizeof(float), size - sizeof(float));
    size_t buffer_size = size - sizeof(float);

    // Call the function-under-test
    cbor_encode_half(value, buffer, buffer_size);

    // Clean up the allocated buffer
    delete[] buffer;

    return 0;
}