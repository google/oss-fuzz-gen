#include <stddef.h>
#include <stdint.h>

extern int nc_put_vars_schar(int ncid, int varid, const size_t *start, const size_t *count, const ptrdiff_t *stride, const signed char *values);

int LLVMFuzzerTestOneInput_169(const uint8_t *data, size_t size) {
    // Ensure there is enough data to fill the parameters
    if (size < sizeof(size_t) * 3 + sizeof(ptrdiff_t) * 3 + sizeof(signed char) * 3) {
        return 0;
    }

    // Initialize parameters
    int ncid = (int)data[0];
    int varid = (int)data[1];

    const size_t *start = (const size_t *)(data + 2);
    const size_t *count = (const size_t *)(data + 2 + sizeof(size_t));
    const ptrdiff_t *stride = (const ptrdiff_t *)(data + 2 + sizeof(size_t) * 2);

    // The remaining data is used for the values array
    const signed char *values = (const signed char *)(data + 2 + sizeof(size_t) * 2 + sizeof(ptrdiff_t) * 3);

    // Call the function-under-test
    nc_put_vars_schar(ncid, varid, start, count, stride, values);

    return 0;
}