#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <netcdf.h>

int LLVMFuzzerTestOneInput_47(const uint8_t *data, size_t size) {
    // Ensure that the size is sufficient for the parameters
    if (size < sizeof(size_t) * 4 + sizeof(ptrdiff_t) * 2 + sizeof(long long)) {
        return 0;
    }

    // Initialize parameters
    int ncid = 0;  // Assuming a valid netCDF file ID for testing
    int varid = 0; // Assuming a valid variable ID for testing

    // Extract sizes for start, count, stride, and imap arrays
    const size_t *start = (const size_t *)(data);
    const size_t *count = (const size_t *)(data + sizeof(size_t));
    const ptrdiff_t *stride = (const ptrdiff_t *)(data + sizeof(size_t) * 2);
    const ptrdiff_t *imap = (const ptrdiff_t *)(data + sizeof(size_t) * 2 + sizeof(ptrdiff_t));

    // Extract the value for the long long data array
    const long long *value = (const long long *)(data + sizeof(size_t) * 2 + sizeof(ptrdiff_t) * 2);

    // Call the function under test
    int result = nc_put_varm_longlong(ncid, varid, start, count, stride, imap, value);

    // Return 0 to indicate no crash
    return 0;
}