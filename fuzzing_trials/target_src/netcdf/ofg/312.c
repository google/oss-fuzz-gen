#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// Function prototype for the function-under-test
int nc_get_var1_text(int param1, int param2, const size_t *param3, char *param4);

int LLVMFuzzerTestOneInput_312(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient for our parameters
    if (size < sizeof(size_t) + 2 * sizeof(int) + 1) {
        return 0;
    }

    // Extract parameters from the input data
    int param1 = *(int *)data;
    int param2 = *(int *)(data + sizeof(int));
    const size_t *param3 = (const size_t *)(data + 2 * sizeof(int));

    // Allocate memory for the char array and copy data into it
    char *param4 = (char *)malloc(size - 2 * sizeof(int) - sizeof(size_t));
    if (param4 == NULL) {
        return 0;
    }
    memcpy(param4, data + 2 * sizeof(int) + sizeof(size_t), size - 2 * sizeof(int) - sizeof(size_t));
    param4[size - 2 * sizeof(int) - sizeof(size_t) - 1] = '\0';  // Null-terminate the string

    // Call the function-under-test
    nc_get_var1_text(param1, param2, param3, param4);

    // Free the allocated memory
    free(param4);

    return 0;
}