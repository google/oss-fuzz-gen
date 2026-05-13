#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>

// Assuming hdr_field is defined somewhere
struct hdr_field {
    // Add appropriate fields based on the actual definition
    int field1;
    char field2[256];
};

// Function-under-test
int parse_rr(struct hdr_field *);

// Fuzzing harness
int LLVMFuzzerTestOneInput_13(const uint8_t *data, size_t size) {
    if (size < sizeof(struct hdr_field)) {
        // Not enough data to fill hdr_field structure
        return 0;
    }

    struct hdr_field hdr;
    
    // Initialize hdr_field with data
    hdr.field1 = *(int *)(data);
    for (size_t i = 0; i < sizeof(hdr.field2) && i < size - sizeof(int); ++i) {
        hdr.field2[i] = data[sizeof(int) + i];
    }

    // Call the function-under-test
    parse_rr(&hdr);

    return 0;
}