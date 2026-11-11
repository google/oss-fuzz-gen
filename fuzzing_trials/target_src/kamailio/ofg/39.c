#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>

// Assuming the definition of struct allow_body is available
struct allow_body {
    int dummy; // Placeholder member
};

// Function-under-test
void free_allow_body(struct allow_body **body);

int LLVMFuzzerTestOneInput_39(const uint8_t *data, size_t size) {
    // Allocate memory for allow_body
    struct allow_body *body = (struct allow_body *)malloc(sizeof(struct allow_body));
    if (body == NULL) {
        return 0; // Exit if memory allocation fails
    }

    // Initialize the struct with some data
    body->dummy = size > 0 ? data[0] : 1; // Use the first byte of data or a default value

    // Create a pointer to the struct
    struct allow_body *body_ptr = body;

    // Call the function-under-test
    free_allow_body(&body_ptr);

    // Ensure the pointer is set to NULL after freeing
    if (body_ptr != NULL) {
        free(body_ptr);
    }

    return 0;
}