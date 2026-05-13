#include <cstddef>
#include <cstdint>
#include <cstring>

extern "C" {
    #include "cbor.h"
}

extern "C" int LLVMFuzzerTestOneInput_32(const uint8_t *data, size_t size) {
    // Define a buffer with a fixed size for encoding
    unsigned char buffer[128];
    
    // Ensure the buffer is not empty and size is within bounds
    if (size > 0 && size <= sizeof(buffer)) {
        // Copy the input data to the buffer
        std::memcpy(buffer, data, size);
        
        // Call the function-under-test
        size_t result = cbor_encode_indef_array_start(buffer, size);
        
        // Use the result in some way to avoid compiler optimizations
        (void)result;
    }

    return 0;
}