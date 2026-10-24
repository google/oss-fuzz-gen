#include <stdint.h>
#include <stddef.h>
#include <stdio.h>

// Mock function to simulate nc_put_var_int_234 behavior
int nc_put_var_int_234(int ncid, int varid, const int *ip) {
    // Simulate some processing
    if (ip == NULL) {
        return -1; // Simulate error if ip is NULL
    }
    return 0; // Simulate success
}

int LLVMFuzzerTestOneInput_234(const uint8_t *data, size_t size) {
    if (size < sizeof(int) * 3) {
        return 0; // Not enough data to extract three integers
    }

    // Extract three integers from the input data
    int ncid = *((int *)data);
    int varid = *((int *)(data + sizeof(int)));
    const int *ip = (const int *)(data + 2 * sizeof(int));

    // Call the function-under-test
    nc_put_var_int_234(ncid, varid, ip);

    return 0;
}