#include <stddef.h>
#include <stdint.h>

// Assuming the function is defined in an external library
extern int nc_get_var1_long(int ncid, int varid, const size_t *indexp, long *valuep);

int LLVMFuzzerTestOneInput_403(const uint8_t *data, size_t size) {
    if (size < sizeof(int) * 2 + sizeof(size_t) + sizeof(long)) {
        return 0;
    }

    // Extracting parameters from the input data
    int ncid = *((int *)data);
    int varid = *((int *)(data + sizeof(int)));
    const size_t *indexp = (const size_t *)(data + sizeof(int) * 2);
    long value;
    long *valuep = &value;

    // Call the function-under-test
    nc_get_var1_long(ncid, varid, indexp, valuep);

    return 0;
}