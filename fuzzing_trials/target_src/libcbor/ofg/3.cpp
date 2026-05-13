#include <cstdint>
#include <cstddef>
#include <cstring>

extern "C" {
    // Include the necessary header for the function-under-test
    #include "cbor.h"  // Assuming the function is declared in cbor.h

    size_t cbor_encode_negint8(uint8_t value, unsigned char *buffer, size_t buffer_size);
}

extern "C" int LLVMFuzzerTestOneInput_3(const uint8_t *data, size_t size) {
    // Initialize parameters for the function-under-test
    uint8_t value = 0;  // Default value, will be overwritten by data if size > 0
    unsigned char buffer[128];  // A buffer to store the encoded data
    size_t buffer_size = sizeof(buffer);

    // Ensure we have at least 1 byte of data to overwrite the value
    if (size > 0) {
        value = data[0];
    }

    // Call the function-under-test
    cbor_encode_negint8(value, buffer, buffer_size);

    return 0;
}