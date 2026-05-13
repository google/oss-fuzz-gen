#include <stdint.h>
#include <stddef.h>
#include <netcdf.h>

int LLVMFuzzerTestOneInput_298(const uint8_t *data, size_t size) {
    int ncid;
    int ndims;

    // Ensure there is enough data to extract an integer for ncid
    if (size < sizeof(int)) {
        return 0;
    }

    // Extract the ncid from the input data
    ncid = *(const int *)data;

    // Call the function-under-test
    nc_inq_ndims(ncid, &ndims);

    return 0;
}