#include <cstddef>
#include <cstdint>
#include <cstring>

// Assuming the function is defined in an external C library
extern "C" {
    size_t cbor_encode_indef_map_start(unsigned char *buffer, size_t buffer_size);
}

extern "C" int LLVMFuzzerTestOneInput_127(const uint8_t *data, size_t size) {
    // Ensure there is at least some space in the buffer
    size_t buffer_size = size > 1 ? size : 2; // Ensure buffer can hold at least two bytes

    // Allocate buffer
    unsigned char *buffer = new unsigned char[buffer_size];

    // Initialize buffer with the input data or a default value
    if (size > 1) {
        memcpy(buffer, data, size);
    } else {
        // Initialize buffer with a default value if size is 0 or 1
        buffer[0] = 0xBF; // Start of an indefinite map in CBOR
        buffer[1] = 0xFF; // End of an indefinite map in CBOR
    }

    // Call the function-under-test
    // Ensure the buffer is not empty and has valid size to potentially increase code coverage
    if (buffer_size > 1) {
        cbor_encode_indef_map_start(buffer, buffer_size);
    }

    // Clean up
    delete[] buffer;

    return 0;
}