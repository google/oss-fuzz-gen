#include <cstdint>
#include <cstddef>
#include <cstring> // Include for memset

// Assuming the function-under-test is defined in an external C library
extern "C" {
    size_t cbor_encode_negint32(uint32_t value, unsigned char *buffer, size_t buffer_size);
}

extern "C" int LLVMFuzzerTestOneInput_64(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient to extract a uint32_t value
    if (size < sizeof(uint32_t)) {
        return 0;
    }

    // Extract a uint32_t value from the input data
    uint32_t value = 0;
    for (size_t i = 0; i < sizeof(uint32_t); ++i) {
        value |= (static_cast<uint32_t>(data[i]) << (i * 8));
    }

    // Define a buffer for encoding
    unsigned char buffer[256]; // Arbitrary buffer size for testing
    size_t buffer_size = sizeof(buffer);

    // Clear the buffer to ensure no garbage values
    std::memset(buffer, 0, buffer_size);

    // Call the function-under-test
    size_t encoded_size = cbor_encode_negint32(value, buffer, buffer_size);

    // Check if the function produced any output to ensure code coverage
    if (encoded_size > 0 && encoded_size <= buffer_size) {
        // Process the buffer if needed, e.g., validate the encoded data
        // This part can be expanded based on what the encoding function is supposed to do
        // For instance, you can print or log the buffer content for debugging purposes
        // or add assertions to check the expected output format.

        // Example: Simple validation to ensure the buffer is not empty
        bool non_zero_found = false;
        for (size_t i = 0; i < encoded_size; ++i) {
            if (buffer[i] != 0) {
                non_zero_found = true;
                break;
            }
        }

        // If the buffer is not empty, it indicates some data was encoded
        if (!non_zero_found) {
            // Log or handle the case where the buffer is unexpectedly empty
            // This can be expanded with more sophisticated checks if needed
        }
    } else {
        // If no output is produced, try different inputs or buffer sizes
        // This can be done by modifying the input data or buffer size
        // to explore different execution paths in the function-under-test.
    }

    return 0;
}