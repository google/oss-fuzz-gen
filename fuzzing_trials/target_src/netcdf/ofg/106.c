#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

extern int nc_inq_var_filter(int, int, unsigned int *, size_t *, unsigned int *);

int LLVMFuzzerTestOneInput_106(const uint8_t *data, size_t size) {
    // Ensure the data size is sufficient to extract necessary values
    if (size < sizeof(int) * 2 + sizeof(unsigned int) * 2 + sizeof(size_t)) {
        return 0;
    }

    // Extract integers from data
    int ncid = *((int *)data);
    int varid = *((int *)(data + sizeof(int)));

    // Allocate and initialize unsigned int and size_t variables
    unsigned int filterid = *((unsigned int *)(data + 2 * sizeof(int)));
    size_t param_len = *((size_t *)(data + 2 * sizeof(int) + sizeof(unsigned int)));
    unsigned int params = *((unsigned int *)(data + 2 * sizeof(int) + sizeof(unsigned int) + sizeof(size_t)));

    // Call the function-under-test
    nc_inq_var_filter(ncid, varid, &filterid, &param_len, &params);

    return 0;
}