#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

extern int nc_get_varm_ushort(int ncid, int varid, const size_t *start, const size_t *count, const ptrdiff_t *stride, const ptrdiff_t *imap, unsigned short *value);

int LLVMFuzzerTestOneInput_133(const uint8_t *data, size_t size) {
    if (size < sizeof(int) * 2 + sizeof(size_t) * 2 + sizeof(ptrdiff_t) * 2 + sizeof(unsigned short)) {
        return 0; // Not enough data to fill all parameters
    }

    int ncid = *(const int *)(data);
    int varid = *(const int *)(data + sizeof(int));

    const size_t *start = (const size_t *)(data + sizeof(int) * 2);
    const size_t *count = (const size_t *)(data + sizeof(int) * 2 + sizeof(size_t));

    const ptrdiff_t *stride = (const ptrdiff_t *)(data + sizeof(int) * 2 + sizeof(size_t) * 2);
    const ptrdiff_t *imap = (const ptrdiff_t *)(data + sizeof(int) * 2 + sizeof(size_t) * 2 + sizeof(ptrdiff_t));

    unsigned short value;
    unsigned short *value_ptr = &value;

    // Call the function-under-test
    nc_get_varm_ushort(ncid, varid, start, count, stride, imap, value_ptr);

    return 0;
}