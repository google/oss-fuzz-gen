#include <stddef.h>
#include <stdint.h>

// Assuming the function is declared in some header file
int nc_get_var1_short(int ncid, int varid, const size_t *indexp, short *valuep);

int LLVMFuzzerTestOneInput_293(const uint8_t *data, size_t size) {
    // Initialize parameters for nc_get_var1_short_293
    int ncid = 1; // Example value, assuming a valid netCDF ID
    int varid = 1; // Example value, assuming a valid variable ID

    // Ensure the data size is sufficient for indexp
    if (size < sizeof(size_t)) {
        return 0;
    }

    // Use the data to initialize indexp
    size_t index = *((const size_t *)data);
    const size_t *indexp = &index;

    // Initialize a short variable to store the result
    short value = 0;
    short *valuep = &value;

    // Call the function-under-test
    nc_get_var1_short(ncid, varid, indexp, valuep);

    return 0;
}