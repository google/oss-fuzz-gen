#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h> // Include for memcpy

extern "C" {
    // Assume the function is defined in an external C library
    size_t cbor_encode_map_start(size_t, unsigned char *, size_t);
}

extern "C" int LLVMFuzzerTestOneInput_76(const uint8_t *data, size_t size) {
    // Ensure there is enough data to extract parameters
    if (size < 2) {
        return 0;
    }

    // Extract the first byte as the map size
    size_t map_size = static_cast<size_t>(data[0]);

    // Copy the rest of the data to a separate buffer to avoid modifying the const input data
    size_t buffer_size = size - 1;
    unsigned char *buffer = (unsigned char *)malloc(buffer_size);
    if (buffer == NULL) {
        return 0; // Handle memory allocation failure
    }
    memcpy(buffer, data + 1, buffer_size);

    // Call the function-under-test
    cbor_encode_map_start(map_size, buffer, buffer_size);

    // Free the allocated buffer
    free(buffer);

    return 0;
}