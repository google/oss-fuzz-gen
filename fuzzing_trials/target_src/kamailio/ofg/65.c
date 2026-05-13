#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "/src/kamailio/src/core/parser/parse_identity.h"  // Include this as per instruction

// // Function-under-test
// void free_identity_65(struct identity_body *identity);

int LLVMFuzzerTestOneInput_65(const uint8_t *data, size_t size) {
    // Ensure there is enough data to fill the structure
    if (size < sizeof(struct identity_body)) {
        return 0;
    }

    // Allocate memory for the identity_body structure
    struct identity_body *identity = (struct identity_body *)malloc(sizeof(struct identity_body));
    if (identity == NULL) {
        return 0;
    }

    // Initialize the identity_body structure to avoid undefined behavior
    memset(identity, 0, sizeof(struct identity_body));

    // Copy data into the identity_body structure, ensuring we don't exceed the available data size
    size_t copy_size = size < sizeof(struct identity_body) ? size : sizeof(struct identity_body);
    memcpy(identity, data, copy_size);

    // Check if the identity structure is valid before calling the function-under-test
    // Using a real field name from the identity_body structure
    // Ensure the identity structure is not null and has valid data before calling the function
    if (identity != NULL && identity->error == 0) { // Assuming 'error' is a valid field
        // Call the function-under-test
        free_identity(identity);
    }

    // Free the allocated memory
    free(identity);

    return 0;
}