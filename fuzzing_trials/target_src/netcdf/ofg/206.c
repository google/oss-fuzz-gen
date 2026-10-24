#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

// Function prototype for the function-under-test
int nc_get_vara_longlong(int ncid, int varid, const size_t *start, const size_t *count, long long *value);

int LLVMFuzzerTestOneInput_206(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient to extract required values
    if (size < sizeof(int) * 2 + sizeof(size_t) * 2 + sizeof(long long)) {
        return 0;
    }

    // Extracting values from the input data
    int ncid = *(const int *)(data);
    int varid = *(const int *)(data + sizeof(int));
    size_t start[1] = { *(const size_t *)(data + sizeof(int) * 2) };
    size_t count[1] = { *(const size_t *)(data + sizeof(int) * 2 + sizeof(size_t)) };
    long long value[1];

    // Call the function-under-test
    nc_get_vara_longlong(ncid, varid, start, count, value);

    return 0;
}