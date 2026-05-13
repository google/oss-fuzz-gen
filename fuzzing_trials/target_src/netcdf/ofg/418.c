#include <stdint.h>
#include <stddef.h>
#include <netcdf.h>

int LLVMFuzzerTestOneInput_418(const uint8_t *data, size_t size) {
    // Ensure that the size is large enough to extract three integers
    if (size < 3 * sizeof(int)) {
        return 0;
    }

    // Extract three integers from the input data
    int ncid = *((const int *)data);
    int varid = *((const int *)(data + sizeof(int)));
    int fletcher32 = *((const int *)(data + 2 * sizeof(int)));

    // Call the function-under-test
    nc_def_var_fletcher32(ncid, varid, fletcher32);

    return 0;
}