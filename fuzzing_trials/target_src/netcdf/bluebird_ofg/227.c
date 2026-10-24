#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

// Assuming the function nc_get_var1 is declared in an external library
// The actual implementation should be linked during compilation
extern int nc_get_var1(int ncid, int varid, const size_t *indexp, void *valuep);

int LLVMFuzzerTestOneInput_227(const uint8_t *data, size_t size) {
    // Ensure there's enough data to extract parameters
    if (size < sizeof(int) * 2 + sizeof(size_t)) {
        return 0;
    }

    // Extract parameters from the input data
    int ncid = *(const int *)(data);
    int varid = *(const int *)(data + sizeof(int));
    const size_t *indexp = (const size_t *)(data + sizeof(int) * 2);

    // Create a buffer for the value to be retrieved
    // Assuming the value is of type int for demonstration purposes
    int value;
    void *valuep = (void *)&value;

    // Call the function-under-test
    nc_get_var1(ncid, varid, indexp, valuep);

    return 0;
}