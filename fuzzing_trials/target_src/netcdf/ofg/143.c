#include <stdint.h>
#include <stddef.h>
#include <netcdf.h>

int LLVMFuzzerTestOneInput_143(const uint8_t *data, size_t size) {
    // Ensure the input data is large enough to extract three integers
    if (size < sizeof(int) * 3) {
        return 0;
    }

    // Extract three integers from the input data
    int ncid = *(const int *)(data);
    int varid = *(const int *)(data + sizeof(int));
    int endian_mode;

    // Call the function-under-test
    int result = nc_inq_var_endian(ncid, varid, &endian_mode);

    // Use the result and endian_mode in some way to avoid compiler optimizations
    if (result == NC_NOERR) {
        // Do something with endian_mode if needed
        (void)endian_mode; // Suppress unused variable warning
    }

    return 0;
}