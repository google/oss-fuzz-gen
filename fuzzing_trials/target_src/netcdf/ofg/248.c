#include <stdint.h>
#include <stddef.h>
#include <netcdf.h>

int LLVMFuzzerTestOneInput_248(const uint8_t *data, size_t size) {
    // Ensure there is enough data to extract parameters
    if (size < sizeof(int) * 3 + 1) {
        return 0;
    }

    // Extract parameters from the input data
    int ncid = *(const int *)(data);
    int varid = *(const int *)(data + sizeof(int));
    int no_fill = *(const int *)(data + 2 * sizeof(int));
    const void *fill_value = (const void *)(data + 3 * sizeof(int));

    // Call the function-under-test
    nc_def_var_fill(ncid, varid, no_fill, fill_value);

    return 0;
}