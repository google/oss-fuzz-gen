#include <cstddef>
#include <cstdint>
#include <cbor.h>

extern "C" {
    // Function signature from the project
    size_t cbor_encode_map_start(size_t, unsigned char *, size_t);
}

extern "C" int LLVMFuzzerTestOneInput_75(const uint8_t *data, size_t size) {
    // Ensure there's enough data to avoid out-of-bounds access
    if (size < 2) return 0;

    // Initialize variables for the function-under-test
    size_t map_size = static_cast<size_t>(data[0]); // Use the first byte for map size
    unsigned char *buffer = new unsigned char[size - 1]; // Allocate buffer for encoding
    size_t buffer_size = size - 1; // Remaining size for buffer

    // Call the function-under-test
    cbor_encode_map_start(map_size, buffer, buffer_size);

    // Clean up
    delete[] buffer;

    return 0;
}