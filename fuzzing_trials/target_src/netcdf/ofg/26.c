#include <stddef.h>
#include <stdint.h>

extern int nc_get_varm_float(int, int, const size_t *, const size_t *, const ptrdiff_t *, const ptrdiff_t *, float *);

int LLVMFuzzerTestOneInput_26(const uint8_t *data, size_t size) {
    if (size < sizeof(size_t) * 2 + sizeof(ptrdiff_t) * 2 + sizeof(float)) {
        return 0;
    }

    int ncid = 1; // Example non-zero value
    int varid = 1; // Example non-zero value

    const size_t *startp = (const size_t *)data;
    const size_t *countp = (const size_t *)(data + sizeof(size_t));
    const ptrdiff_t *stridep = (const ptrdiff_t *)(data + sizeof(size_t) * 2);
    const ptrdiff_t *imapp = (const ptrdiff_t *)(data + sizeof(size_t) * 2 + sizeof(ptrdiff_t));
    float value = 0.0f; // Example non-zero value
    float *op = &value;

    nc_get_varm_float(ncid, varid, startp, countp, stridep, imapp, op);

    return 0;
}