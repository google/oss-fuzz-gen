#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// Assuming the structure of gps_lexer_t is defined somewhere
struct gps_lexer_t {
    // Placeholder fields for demonstration purposes
    int field1;
    char field2[256];
    // Add other fields as necessary
};

// Function-under-test
void packet_reset(struct gps_lexer_t *lexer);

int LLVMFuzzerTestOneInput_54(const uint8_t *data, size_t size) {
    // Allocate and initialize a gps_lexer_t structure
    struct gps_lexer_t lexer;
    
    // Initialize the structure fields with non-NULL values
    lexer.field1 = 0;
    memset(lexer.field2, 'A', sizeof(lexer.field2) - 1);
    lexer.field2[sizeof(lexer.field2) - 1] = '\0'; // Null-terminate the string

    // Call the function-under-test
    packet_reset(&lexer);

    return 0;
}