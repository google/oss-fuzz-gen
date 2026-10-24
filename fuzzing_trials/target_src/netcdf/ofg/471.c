#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <netcdf.h>

int LLVMFuzzerTestOneInput_471(const uint8_t *data, size_t size) {
    // Ensure that the size is sufficient to extract two integers
    if (size < 2 * sizeof(int)) {
        return 0;
    }

    // Extract the first integer from the data
    int ncid = *(const int *)data;
    data += sizeof(int);
    size -= sizeof(int);

    // Extract the second integer from the data
    int varid = *(const int *)data;
    data += sizeof(int);
    size -= sizeof(int);

    // Allocate memory for the dimids array
    int dimids[10]; // Assuming a maximum of 10 dimensions for simplicity

    // Call the function-under-test
    nc_inq_vardimid(ncid, varid, dimids);

    return 0;
}