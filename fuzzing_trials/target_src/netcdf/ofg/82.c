#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

extern int nc_get_vars_uint(int arg1, int arg2, const size_t *start, const size_t *count, const ptrdiff_t *stride, unsigned int *data);

int LLVMFuzzerTestOneInput_82(const uint8_t *data, size_t size) {
    if (size < sizeof(size_t) * 2 + sizeof(ptrdiff_t) + sizeof(unsigned int)) {
        return 0; // Not enough data to fill all parameters
    }

    int arg1 = (int)data[0];
    int arg2 = (int)data[1];

    size_t start[1];
    size_t count[1];
    ptrdiff_t stride[1];
    unsigned int output[1];

    memcpy(start, data + 2, sizeof(size_t));
    memcpy(count, data + 2 + sizeof(size_t), sizeof(size_t));
    memcpy(stride, data + 2 + 2 * sizeof(size_t), sizeof(ptrdiff_t));
    memcpy(output, data + 2 + 2 * sizeof(size_t) + sizeof(ptrdiff_t), sizeof(unsigned int));

    nc_get_vars_uint(arg1, arg2, start, count, stride, output);

    return 0;
}