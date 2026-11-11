#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// Function prototype for the function-under-test
int nc_get_var_text(int param1, int param2, char *param3);

int LLVMFuzzerTestOneInput_217(const uint8_t *data, size_t size) {
    // Ensure we have enough data for the parameters
    if (size < 8) {
        return 0; // Not enough data to proceed
    }

    // Extract the first and second integers from the data
    int param1 = *((int*)data);
    int param2 = *((int*)(data + 4));

    // Ensure there is space for the string and a null terminator
    size_t string_length = size - 8;
    char *param3 = (char *)malloc(string_length + 1);
    if (param3 == NULL) {
        return 0; // Memory allocation failed
    }

    // Copy the remaining data into the string and null-terminate it
    memcpy(param3, data + 8, string_length);
    param3[string_length] = '\0';

    // Call the function-under-test
    nc_get_var_text(param1, param2, param3);

    // Clean up
    free(param3);

    return 0;
}