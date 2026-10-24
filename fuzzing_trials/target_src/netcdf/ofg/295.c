#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

extern int nc_get_var1_ulonglong(int ncid, int varid, const size_t *indexp, unsigned long long *valuep);

int LLVMFuzzerTestOneInput_295(const uint8_t *data, size_t size) {
    // Ensure the size is sufficient to extract required parameters
    if (size < sizeof(size_t) + sizeof(unsigned long long)) {
        return 0;
    }

    // Extract parameters from the input data
    int ncid = (int)data[0];  // Use the first byte for ncid
    int varid = (int)data[1]; // Use the second byte for varid

    // Use the remaining data for the indexp and valuep
    const size_t *indexp = (const size_t *)(data + 2);
    unsigned long long *valuep = (unsigned long long *)(data + 2 + sizeof(size_t));

    // Call the function-under-test
    nc_get_var1_ulonglong(ncid, varid, indexp, valuep);

    return 0;
}