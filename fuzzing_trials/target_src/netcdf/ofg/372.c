#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>  // Include for memset

extern int nc_get_vars_ulonglong(int, int, const size_t *, const size_t *, const ptrdiff_t *, unsigned long long *);

int LLVMFuzzerTestOneInput_372(const uint8_t *data, size_t size) {
    // Ensure we have enough data to fill all parameters
    if (size < 6 * sizeof(size_t) + 2 * sizeof(int) + sizeof(ptrdiff_t)) {
        return 0;
    }

    // Extract parameters from the input data
    int param1 = *((int *)data);
    int param2 = *((int *)(data + sizeof(int)));

    const size_t *start = (const size_t *)(data + 2 * sizeof(int));
    const size_t *count = (const size_t *)(data + 2 * sizeof(int) + sizeof(size_t));

    const ptrdiff_t *stride = (const ptrdiff_t *)(data + 2 * sizeof(int) + 2 * sizeof(size_t));

    unsigned long long output;
    unsigned long long *value = &output;

    // Ensure start, count, and stride are valid and meaningful
    size_t start_buffer[3];
    size_t count_buffer[3];
    ptrdiff_t stride_buffer[3];

    memcpy(start_buffer, start, 3 * sizeof(size_t));
    memcpy(count_buffer, count, 3 * sizeof(size_t));
    memcpy(stride_buffer, stride, 3 * sizeof(ptrdiff_t));

    // Set default values if needed
    for (int i = 0; i < 3; ++i) {
        if (start_buffer[i] == 0) start_buffer[i] = 1;
        if (count_buffer[i] == 0) count_buffer[i] = 1;
        if (stride_buffer[i] == 0) stride_buffer[i] = 1;
    }

    // Call the function-under-test with meaningful parameters
    nc_get_vars_ulonglong(param1, param2, start_buffer, count_buffer, stride_buffer, value);

    return 0;
}