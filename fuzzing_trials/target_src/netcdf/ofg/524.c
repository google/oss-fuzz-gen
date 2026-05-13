#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

// Mock function signature for nc_put_var_string_524
int nc_put_var_string_524(int ncid, int varid, const char **op) {
    // Mock implementation of the function
    printf("ncid: %d, varid: %d, op: %s\n", ncid, varid, op[0]);
    return 0; // Return success
}

#ifdef __cplusplus
extern "C" {
#endif

int LLVMFuzzerTestOneInput_524(const uint8_t *data, size_t size) {
    if (size < 2) {
        return 0; // Not enough data to proceed
    }

    // Initialize parameters for nc_put_var_string_524
    int ncid = data[0]; // Use the first byte as ncid
    int varid = data[1]; // Use the second byte as varid

    // Create a string from the remaining data
    size_t string_size = size - 2;
    char *str = (char *)malloc(string_size + 1);
    if (str == NULL) {
        return 0; // Memory allocation failed
    }
    memcpy(str, data + 2, string_size);
    str[string_size] = '\0'; // Null-terminate the string

    // Create an array of string pointers
    const char *op[] = {str};

    // Call the function-under-test
    nc_put_var_string_524(ncid, varid, op);

    // Clean up
    free(str);

    return 0;
}

#ifdef __cplusplus
}
#endif