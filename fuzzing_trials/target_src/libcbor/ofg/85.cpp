#include <cstddef>
#include <cstdint>
#include <cstring>
#include <cstdio>

extern "C" {
    size_t cbor_encode_double(double value, unsigned char *buffer, size_t buffer_size);
}

extern "C" int LLVMFuzzerTestOneInput_85(const uint8_t *data, size_t size) {
    // Ensure there is enough data to extract a double value
    if (size < sizeof(double)) {
        return 0;
    }

    // Extract a double value from the input data
    double value;
    memcpy(&value, data, sizeof(double));

    // Prepare a buffer for encoding
    size_t buffer_size = 256; // Arbitrary buffer size for encoding
    unsigned char buffer[256];

    // Call the function-under-test
    cbor_encode_double(value, buffer, buffer_size);

    return 0;
}