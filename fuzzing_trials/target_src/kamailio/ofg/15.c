#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>

// Define the exp_body_t structure
typedef struct {
    int data; // Example member, adjust according to actual definition
} exp_body_t;

// Function-under-test
void free_expires(exp_body_t **exp);

// LLVMFuzzerTestOneInput function
int LLVMFuzzerTestOneInput_15(const uint8_t *data, size_t size) {
    // Allocate memory for exp_body_t pointer
    exp_body_t *exp = (exp_body_t *)malloc(sizeof(exp_body_t));
    if (exp == NULL) {
        return 0; // Exit if memory allocation fails
    }

    // Initialize exp_body_t with some data
    if (size >= sizeof(int)) {
        // Use the first sizeof(int) bytes of data to initialize exp->data
        exp->data = *((int *)data);
    } else {
        exp->data = 0; // Default value if not enough data
    }

    // Create a pointer to exp_body_t
    exp_body_t *exp_ptr = exp;

    // Call the function-under-test
    free_expires(&exp_ptr);

    // Free allocated memory if not already freed by free_expires
    if (exp_ptr != NULL) {
        free(exp_ptr);
    }

    return 0;
}