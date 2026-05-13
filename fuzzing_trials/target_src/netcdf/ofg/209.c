#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

extern int nc_put_varm_ubyte(int ncid, int varid, const size_t *start, const size_t *count, const ptrdiff_t *stride, const ptrdiff_t *imap, const unsigned char *op);

int LLVMFuzzerTestOneInput_209(const uint8_t *data, size_t size) {
    if (size < 6) {
        return 0;
    }

    // Initialize parameters for nc_put_varm_ubyte
    int ncid = (int)data[0];
    int varid = (int)data[1];

    size_t start[] = { (size_t)data[2] };
    size_t count[] = { (size_t)data[3] };
    ptrdiff_t stride[] = { (ptrdiff_t)data[4] };
    ptrdiff_t imap[] = { (ptrdiff_t)data[5] };

    // Ensure there's enough data for the op array
    if (size < 6 + count[0]) {
        return 0;
    }

    const unsigned char *op = data + 6;

    // Call the function-under-test
    nc_put_varm_ubyte(ncid, varid, start, count, stride, imap, op);

    return 0;
}

#ifdef __cplusplus
}
#endif