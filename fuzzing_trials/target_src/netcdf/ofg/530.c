#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

extern int nc_put_vars_double(int ncid, int varid, const size_t *start, const size_t *count, const ptrdiff_t *stride, const double *data);

int LLVMFuzzerTestOneInput_530(const uint8_t *data, size_t size) {
    if (size < sizeof(int) * 2 + sizeof(size_t) * 2 + sizeof(ptrdiff_t) + sizeof(double)) {
        return 0; // Not enough data to fill all parameters
    }

    int ncid = *(const int *)data;
    int varid = *(const int *)(data + sizeof(int));

    const size_t *start = (const size_t *)(data + sizeof(int) * 2);
    const size_t *count = (const size_t *)(data + sizeof(int) * 2 + sizeof(size_t));

    const ptrdiff_t *stride = (const ptrdiff_t *)(data + sizeof(int) * 2 + sizeof(size_t) * 2);

    const double *double_data = (const double *)(data + sizeof(int) * 2 + sizeof(size_t) * 2 + sizeof(ptrdiff_t));

    // Call the function-under-test
    nc_put_vars_double(ncid, varid, start, count, stride, double_data);

    return 0;
}