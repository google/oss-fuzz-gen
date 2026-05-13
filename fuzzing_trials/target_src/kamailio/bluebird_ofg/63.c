#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>

// Assuming exp_body_t is defined elsewhere
typedef struct {
    int some_field; // Example field
} exp_body_t;

// Function-under-test
void free_expires(exp_body_t **exp_body);

// Fuzzing harness
int LLVMFuzzerTestOneInput_63(const uint8_t *data, size_t size) {
    exp_body_t *exp_body = NULL;

    // Ensure size is sufficient to create at least one exp_body_t
    if (size >= sizeof(exp_body_t)) {
        // Allocate memory for exp_body
        exp_body = (exp_body_t *)malloc(sizeof(exp_body_t));
        if (exp_body == NULL) {
            return 0; // Exit if memory allocation fails
        }

        // Initialize exp_body with data
        exp_body->some_field = (int)data[0]; // Example initialization

        // Call the function-under-test
        free_expires(&exp_body);

        // Ensure exp_body is freed
        if (exp_body != NULL) {
            free(exp_body);
        }
    }

    return 0;
}