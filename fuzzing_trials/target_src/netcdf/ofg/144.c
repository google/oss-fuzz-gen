#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>

// Assume the function is defined in a library we are linking against
extern int nc_inq_var_endian(int ncid, int varid, int *endianp);

int LLVMFuzzerTestOneInput_144(const uint8_t *data, size_t size) {
    // Ensure there's enough data to extract the required integers
    if (size < sizeof(int) * 2) {
        return 0;
    }

    // Extract integers from the input data
    int ncid = *(const int *)(data);
    int varid = *(const int *)(data + sizeof(int));

    // Initialize the output parameter
    int endian;
    int *endianp = &endian;

    // Call the function-under-test
    nc_inq_var_endian(ncid, varid, endianp);

    return 0;
}