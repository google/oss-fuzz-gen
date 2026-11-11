#include <stddef.h>
#include <stdint.h>

extern int nc_get_vars_uint(int, int, const size_t *, const size_t *, const ptrdiff_t *, unsigned int *);

int LLVMFuzzerTestOneInput_146(const uint8_t *data, size_t size) {
    if (size < sizeof(size_t) * 2 + sizeof(ptrdiff_t) + sizeof(unsigned int)) {
        return 0; // Not enough data to proceed
    }

    int arg1 = (int)data[0];
    int arg2 = (int)data[1];

    const size_t start[] = { (size_t)data[2], (size_t)data[3] };
    const size_t count[] = { (size_t)data[4], (size_t)data[5] };
    const ptrdiff_t stride[] = { (ptrdiff_t)data[6] };

    unsigned int output;
    
    nc_get_vars_uint(arg1, arg2, start, count, stride, &output);

    return 0;
}