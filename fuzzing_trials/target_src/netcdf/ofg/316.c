#include <stdint.h>
#include <stddef.h>
#include <stdio.h>

// Assume the function-under-test is defined elsewhere
extern int nc_put_var_float(int ncid, int varid, const float *fp);

int LLVMFuzzerTestOneInput_316(const uint8_t *data, size_t size) {
    int ncid = 1;  // Using a non-zero, arbitrary value for ncid
    int varid = 1; // Using a non-zero, arbitrary value for varid

    // Ensure there is at least enough data for one float
    if (size < sizeof(float)) {
        return 0;
    }

    // Cast the data to float pointer
    const float *fp = (const float *)data;

    // Call the function-under-test
    nc_put_var_float(ncid, varid, fp);

    return 0;
}