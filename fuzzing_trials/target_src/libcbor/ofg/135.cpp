#include <cstddef>
#include <cstdint>
#include <cstring>
#include <cstdio>

extern "C" {
    size_t cbor_encode_indef_string_start(unsigned char *buffer, size_t buffer_size);
}

extern "C" int LLVMFuzzerTestOneInput_135(const uint8_t *data, size_t size) {
    // Ensure the buffer is not NULL and has a reasonable size
    unsigned char buffer[1024];

    // If the size is 0, return immediately as there's nothing to process
    if (size == 0) {
        return 0;
    }

    // Copy the input data to the buffer, ensuring not to overflow
    size_t copy_size = size < sizeof(buffer) ? size : sizeof(buffer);
    memcpy(buffer, data, copy_size);

    // Call the function-under-test
    // Use a meaningful size for the buffer to ensure the function processes it
    cbor_encode_indef_string_start(buffer, copy_size);

    return 0;
}