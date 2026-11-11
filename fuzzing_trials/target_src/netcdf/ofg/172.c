#include <stdint.h>
#include <stddef.h>

// Assume the function nc_def_var_endian is defined elsewhere
int nc_def_var_endian(int ncid, int varid, int endian);

int LLVMFuzzerTestOneInput_172(const uint8_t *data, size_t size) {
    // Ensure there is enough data to extract three integers
    if (size < 3 * sizeof(int)) {
        return 0;
    }

    // Extract three integers from the data
    int ncid = *((const int *)(data));
    int varid = *((const int *)(data + sizeof(int)));
    int endian = *((const int *)(data + 2 * sizeof(int)));

    // Call the function-under-test with the extracted integers
    nc_def_var_endian(ncid, varid, endian);

    return 0;
}