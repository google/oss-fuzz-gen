#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h> // Include for memcpy
#include "gpsd_config.h" // Include the GPSD configuration header
#include "gpsd.h" // Assuming this header contains the definition for gps_lexer_t and rtcm2_decode

int LLVMFuzzerTestOneInput_78(const uint8_t *data, size_t size) {
    // Initialize the gps_lexer_t structure
    struct gps_lexer_t lexer;
    
    // Ensure the data is not NULL and has a minimum size
    if (size == 0) {
        return 0;
    }
    
    // Initialize lexer state if necessary
    memset(&lexer, 0, sizeof(lexer));

    // Set a non-zero options value
    unsigned int options = 1;

    // Process the buffer in chunks that fit within the lexer.inbuffer
    size_t offset = 0;
    while (offset < size) {
        // Determine the size of the current chunk
        size_t chunk_size = (size - offset < sizeof(lexer.inbuffer)) ? size - offset : sizeof(lexer.inbuffer);

        // Copy data into the lexer input buffer
        memcpy(lexer.inbuffer, data + offset, chunk_size);
        lexer.inbuflen = chunk_size;

        // Call the function-under-test
        int result = rtcm2_decode(&lexer, options);

        // Use the result in some way to avoid compiler optimizations removing the call
        // Check if the result indicates successful processing
        if (result > 0) {
            // If successful, break the loop to simulate a meaningful processing
            break;
        }

        // Move to the next chunk
        offset += chunk_size;
    }

    // Additional logic to ensure data is not null and has a meaningful structure
    // This can be done by checking specific bytes or patterns expected by rtcm2_decode
    if (size >= sizeof(lexer.inbuffer)) {
        // Simulate a specific data pattern that might be expected by the function
        lexer.inbuffer[0] = 0xD3; // Example of a sync byte for RTCM messages
        lexer.inbuflen = sizeof(lexer.inbuffer);
        rtcm2_decode(&lexer, options);
    }

    // To enhance coverage, ensure that the function is called with various options
    for (unsigned int test_options = 0; test_options < 4; ++test_options) {
        lexer.inbuflen = size < sizeof(lexer.inbuffer) ? size : sizeof(lexer.inbuffer);
        memcpy(lexer.inbuffer, data, lexer.inbuflen);
        rtcm2_decode(&lexer, test_options);
    }

    return 0;
}