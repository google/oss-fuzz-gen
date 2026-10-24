#include <cstddef>
#include <cstdint>
#include <cstring> // Include this for std::memcpy

// Assuming the function-under-test is defined in an external C library
extern "C" {
    size_t cbor_encode_double(double value, unsigned char *buffer, size_t buffer_size);
}

extern "C" int LLVMFuzzerTestOneInput_86(const uint8_t *data, size_t size) {
    if (size < sizeof(double)) {
        return 0; // Not enough data to extract a double
    }

    // Extract a double value from the input data
    double value;
    std::memcpy(&value, data, sizeof(double));

    // Prepare a buffer for encoding
    size_t buffer_size = 256; // Arbitrary buffer size for testing
    unsigned char buffer[256];

    // Call the function-under-test
    cbor_encode_double(value, buffer, buffer_size);

    return 0;
}