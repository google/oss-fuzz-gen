#include <cstddef>
#include <cstdint>
#include <cstring>

// Assuming the function is defined somewhere in the project
extern "C" {
    size_t cbor_encode_single(float value, unsigned char *buffer, size_t buffer_size);
}

extern "C" int LLVMFuzzerTestOneInput_14(const uint8_t *data, size_t size) {
    // Ensure the size is sufficient to extract a float
    if (size < sizeof(float)) {
        return 0;
    }

    // Extract a float value from the input data
    float value;
    std::memcpy(&value, data, sizeof(float));

    // Define a buffer for encoding
    unsigned char buffer[256];  // Example buffer size, can be adjusted
    size_t buffer_size = sizeof(buffer);

    // Call the function-under-test
    cbor_encode_single(value, buffer, buffer_size);

    return 0;
}