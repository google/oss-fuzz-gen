#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

// Assuming the function is declared in a header file
// #include "netcdf.h" // Replace with actual header if available

// Mock function definition for demonstration purposes
int nc_get_att_ulonglong_436(int ncid, int varid, const char *name, unsigned long long *value) {
    // Dummy implementation
    if (ncid < 0 || varid < 0 || name == NULL || value == NULL) {
        return -1; // Simulate an error for invalid input
    }
    *value = 123456789; // Simulate setting a value
    return 0;
}

int LLVMFuzzerTestOneInput_436(const uint8_t *data, size_t size) {
    // Ensure that the data size is sufficient for the required parameters
    if (size < sizeof(int) * 2 + 1) {
        return 0; // Not enough data to proceed
    }

    // Extract parameters from the input data
    int ncid = *(int *)data;
    int varid = *(int *)(data + sizeof(int));
    const char *name = (const char *)(data + sizeof(int) * 2);

    // Ensure that the name string is null-terminated
    char name_buffer[256];
    size_t name_length = size - sizeof(int) * 2;
    if (name_length >= sizeof(name_buffer)) {
        name_length = sizeof(name_buffer) - 1;
    }
    memcpy(name_buffer, name, name_length);
    name_buffer[name_length] = '\0';

    // Prepare the output parameter
    unsigned long long value = 0;

    // Call the function-under-test
    int result = nc_get_att_ulonglong_436(ncid, varid, name_buffer, &value);

    // Check the result to ensure the function is being exercised
    if (result == 0) {
        // Optionally, print or log the value to verify correct behavior
        // printf("Value: %llu\n", value);
    }

    return 0;
}