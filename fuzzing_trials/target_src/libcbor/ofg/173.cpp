#include <cstdint>
#include <cstddef>
#include <cstring>
#include <algorithm> // Include for std::min

// Assuming the function-under-test is defined in an external C library
extern "C" {
    size_t cbor_encode_tag(uint64_t tag, unsigned char *buffer, size_t buffer_size);
}

extern "C" int LLVMFuzzerTestOneInput_173(const uint8_t *data, size_t size) {
    // Prepare the parameters for cbor_encode_tag
    uint64_t tag = 0;
    unsigned char buffer[256]; // A buffer to hold encoded data
    size_t buffer_size = sizeof(buffer);

    // Ensure that the input data is not empty
    if (size > 0) {
        // Use the first few bytes of data to initialize the tag
        std::memcpy(&tag, data, std::min(sizeof(tag), size));
    }

    // Call the function-under-test
    cbor_encode_tag(tag, buffer, buffer_size);

    return 0;
}