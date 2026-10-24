#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

extern int nc_get_varm_double(int ncid, int varid, const size_t *start, const size_t *count, const ptrdiff_t *stride, const ptrdiff_t *imap, double *data);

int LLVMFuzzerTestOneInput_188(const uint8_t *data, size_t size) {
    // Define and initialize variables to be used as parameters
    int ncid = 1; // Example non-zero value
    int varid = 1; // Example non-zero value

    // Ensure there is enough data to extract necessary values
    if (size < 6 * sizeof(size_t)) {
        return 0;
    }

    // Extract size_t values from data
    size_t start[1];
    size_t count[1];
    ptrdiff_t stride[1];
    ptrdiff_t imap[1];

    start[0] = (size_t)data[0];
    count[0] = (size_t)data[1];
    stride[0] = (ptrdiff_t)data[2];
    imap[0] = (ptrdiff_t)data[3];

    // Allocate memory for the double array
    double *double_data = (double *)malloc(sizeof(double) * count[0]);
    if (double_data == NULL) {
        return 0;
    }

    // Call the function-under-test
    int result = nc_get_varm_double(ncid, varid, start, count, stride, imap, double_data);

    // Free allocated memory
    free(double_data);

    return 0;
}