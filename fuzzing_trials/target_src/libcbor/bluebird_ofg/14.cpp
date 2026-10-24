#include <cstddef>
#include "cstdint"
#include <cstring> // For memcpy

extern "C" {
    // Function-under-test declaration
    size_t cbor_encode_negint(uint64_t value, unsigned char *buffer, size_t buffer_size);
}

extern "C" int LLVMFuzzerTestOneInput_14(const uint8_t *data, size_t size) {
    // Ensure that the size is sufficient for the buffer and to read a uint64_t
    if (size < sizeof(uint64_t)) {
        return 0;
    }

    // Initialize parameters for cbor_encode_negint
    uint64_t value;
    memcpy(&value, data, sizeof(uint64_t)); // Use the first 8 bytes of data as the value

    unsigned char *buffer = new unsigned char[size]; // Allocate buffer with the given size
    size_t buffer_size = size; // Use the size of the input data as the buffer size

    // Call the function-under-test

    // Begin mutation: Producer.REPLACE_ARG_MUTATOR - Replaced argument 2 of cbor_encode_negint
    cbor_encode_negint(value, buffer, 1);
    // End mutation: Producer.REPLACE_ARG_MUTATOR



    // Clean up allocated memory
    delete[] buffer;

    return 0;
}