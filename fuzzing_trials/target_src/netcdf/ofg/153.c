#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>

// Assuming the function is declared in an external library
extern int nc_get_var_uint(int ncid, int varid, unsigned int *value);

int LLVMFuzzerTestOneInput_153(const uint8_t *data, size_t size) {
    if (size < sizeof(int) * 2 + sizeof(unsigned int)) {
        return 0; // Not enough data to fill parameters
    }

    // Initialize parameters
    int ncid = *((int *)data);
    int varid = *((int *)(data + sizeof(int)));
    unsigned int value;

    // Call the function-under-test
    nc_get_var_uint(ncid, varid, &value);

    return 0;
}