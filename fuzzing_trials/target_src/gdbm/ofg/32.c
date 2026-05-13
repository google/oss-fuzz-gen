#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>  // Include this for malloc and free

// Function-under-test
int getyn(const char *, void *);  // Change 'void' to 'void *' for the second parameter

int LLVMFuzzerTestOneInput_32(const uint8_t *data, size_t size) {
    // Ensure the data is null-terminated
    char *null_terminated_data = (char *)malloc(size + 1);
    if (!null_terminated_data) return 0;
    memcpy(null_terminated_data, data, size);
    null_terminated_data[size] = '\0';

    // Create a dummy non-null void* parameter
    int dummy_param = 0;
    void *dummy_void_ptr = &dummy_param;

    // Call the function-under-test with a non-null input
    if (size > 0 && null_terminated_data[0] != '\0') {
        getyn(null_terminated_data, dummy_void_ptr);
    }

    // Clean up
    free(null_terminated_data);
    return 0;
}