#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

extern int nc_get_vars_int(int, int, const size_t *, const size_t *, const ptrdiff_t *, int *);

int LLVMFuzzerTestOneInput_336(const uint8_t *data, size_t size) {
    // Check if the size is sufficient for our needs
    if (size < sizeof(size_t) * 3 + sizeof(ptrdiff_t) + sizeof(int) * 2) {
        return 0;
    }

    // Initialize variables
    int param1 = (int)data[0];
    int param2 = (int)data[1];

    const size_t start[] = { (size_t)data[2], (size_t)data[3] };
    const size_t count[] = { (size_t)data[4], (size_t)data[5] };
    const ptrdiff_t stride[] = { (ptrdiff_t)data[6] };

    int output;
    
    // Call the function-under-test
    nc_get_vars_int(param1, param2, start, count, stride, &output);

    return 0;
}