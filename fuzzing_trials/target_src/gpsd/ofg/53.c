#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

// Assuming the definition of gps_lexer_t is available
struct gps_lexer_t {
    // Add relevant fields here based on the actual definition
    int dummy_field; // Example field
    // Add other fields as necessary
    char buffer[256]; // Example buffer to simulate a realistic structure
};

// Function-under-test
void packet_reset(struct gps_lexer_t *lexer);

int LLVMFuzzerTestOneInput_53(const uint8_t *data, size_t size) {
    // Allocate and initialize gps_lexer_t structure
    struct gps_lexer_t lexer;
    
    // Initialize all fields of gps_lexer_t to zero
    memset(&lexer, 0, sizeof(struct gps_lexer_t));

    // If there are specific fields that need initialization, do it here
    lexer.dummy_field = 1; // Initialize with a non-zero value if necessary

    // Ensure that the size does not exceed the buffer size of gps_lexer_t
    size_t copy_size = size < sizeof(lexer.buffer) ? size : sizeof(lexer.buffer) - 1;
    memcpy(lexer.buffer, data, copy_size);
    lexer.buffer[copy_size] = '\0'; // Null-terminate to prevent overflow

    // Call the function-under-test
    packet_reset(&lexer);

    return 0;
}