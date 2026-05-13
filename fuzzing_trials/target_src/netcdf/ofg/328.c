#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern int nc_put_vars_ulonglong(int, int, const size_t *, const size_t *, const ptrdiff_t *, const unsigned long long *);

int LLVMFuzzerTestOneInput_328(const uint8_t *data, size_t size) {
    if (size < sizeof(size_t) * 3 + sizeof(ptrdiff_t) + sizeof(unsigned long long)) {
        return 0; // Not enough data to fill all parameters
    }

    int param1 = 1; // Example value for the first parameter
    int param2 = 1; // Example value for the second parameter

    size_t start[1];
    size_t count[1];
    ptrdiff_t stride[1];
    unsigned long long value[1];

    // Initialize the parameters from the input data
    memcpy(start, data, sizeof(size_t));
    memcpy(count, data + sizeof(size_t), sizeof(size_t));
    memcpy(stride, data + 2 * sizeof(size_t), sizeof(ptrdiff_t));
    memcpy(value, data + 2 * sizeof(size_t) + sizeof(ptrdiff_t), sizeof(unsigned long long));

    // Call the function-under-test
    nc_put_vars_ulonglong(param1, param2, start, count, stride, value);

    return 0;
}