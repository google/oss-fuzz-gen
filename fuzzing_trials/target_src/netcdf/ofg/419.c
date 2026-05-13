#include <stdint.h>
#include <stddef.h>
#include <netcdf.h>

// Function-under-test
int nc_def_var_fletcher32(int ncid, int varid, int fletcher32);

int LLVMFuzzerTestOneInput_419(const uint8_t *data, size_t size) {
    // Check if the input size is sufficient to extract meaningful values
    if (size < 3 * sizeof(int)) {
        return 0; // Not enough data to proceed
    }

    // Extract values from the data buffer
    int ncid = *(const int *)(data);  // Extract integer for ncid
    int varid = *(const int *)(data + sizeof(int)); // Extract integer for varid
    int fletcher32 = *(const int *)(data + 2 * sizeof(int)); // Extract integer for fletcher32

    // Call the function-under-test
    nc_def_var_fletcher32(ncid, varid, fletcher32);

    return 0;
}