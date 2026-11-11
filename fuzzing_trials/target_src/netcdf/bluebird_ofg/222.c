#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>

// Assume the function is defined in some library
extern int nc_get_var1_int(int ncid, int varid, const size_t *indexp, int *ip);

int LLVMFuzzerTestOneInput_222(const uint8_t *data, size_t size) {
    // Check if the size is sufficient to extract the required parameters
    if (size < sizeof(int) * 2 + sizeof(size_t)) {
        return 0;
    }

    // Extract parameters from the input data
    int ncid = *((int*)data);
    int varid = *((int*)(data + sizeof(int)));
    const size_t *indexp = (const size_t*)(data + sizeof(int) * 2);
    int ip;

    // Call the function-under-test
    nc_get_var1_int(ncid, varid, indexp, &ip);

    return 0;
}