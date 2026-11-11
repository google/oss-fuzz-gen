#include <cstddef>
#include <cstdint>

// Include the necessary headers for the function-under-test
extern "C" {
    #include "cbor.h" // Assuming the function is declared in cbor.h
}

// Fuzzing harness for cbor_encode_array_start
extern "C" int LLVMFuzzerTestOneInput_152(const uint8_t *data, size_t size) {
    // Ensure that the size is large enough to avoid buffer overflows
    if (size < 2) {
        return 0;
    }

    // Initialize parameters for cbor_encode_array_start
    size_t array_size = static_cast<size_t>(data[0]); // Use the first byte for array size
    unsigned char *buffer = new unsigned char[size - 1]; // Allocate buffer for encoding
    size_t buffer_size = size - 1; // Remaining size for the buffer

    // Call the function-under-test
    size_t encoded_size = cbor_encode_array_start(array_size, buffer, buffer_size);

    // Clean up
    delete[] buffer;

    return 0;
}