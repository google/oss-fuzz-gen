#include <cstddef>
#include <cstdint>
#include <cstring>
#include <cstdio>

extern "C" {
    size_t cbor_encode_half(float value, unsigned char *buffer, size_t buffer_size);
}

extern "C" int LLVMFuzzerTestOneInput_80(const uint8_t *data, size_t size) {
    // Declare and initialize the float value
    float value = 0.0f;

    // Ensure size is large enough to copy a float value
    if (size >= sizeof(float)) {
        // Copy data into the float value
        memcpy(&value, data, sizeof(float));
    }

    // Declare and initialize the buffer
    unsigned char buffer[256];
    size_t buffer_size = sizeof(buffer);

    // Call the function-under-test
    size_t encoded_size = cbor_encode_half(value, buffer, buffer_size);

    // Print the encoded size for debugging purposes
    printf("Encoded size: %zu\n", encoded_size);

    return 0;
}