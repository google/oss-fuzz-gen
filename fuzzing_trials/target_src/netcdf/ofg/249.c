#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

// Assume the function is defined in an external library
extern int nc_def_var_fill(int ncid, int varid, int no_fill, const void *fill_value);

int LLVMFuzzerTestOneInput_249(const uint8_t *data, size_t size) {
    // Check if the input size is sufficient to extract necessary parameters
    if (size < sizeof(int) * 3 + 1) {
        return 0;
    }

    // Extract parameters from the input data
    int ncid = *((int *)data);
    int varid = *((int *)(data + sizeof(int)));
    int no_fill = *((int *)(data + 2 * sizeof(int)));
    
    // Ensure no_fill is either 0 or 1 for valid boolean interpretation
    no_fill = no_fill % 2;

    // Use the remaining data as the fill_value
    const void *fill_value = (const void *)(data + 3 * sizeof(int));

    // Call the function-under-test
    nc_def_var_fill(ncid, varid, no_fill, fill_value);

    return 0;
}