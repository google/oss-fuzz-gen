#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <netcdf.h>

int LLVMFuzzerTestOneInput_73(const uint8_t *data, size_t size) {
    // Ensure we have enough data to extract three integers
    if (size < 3 * sizeof(int)) {
        return 0;
    }

    // Extract three integers from the input data
    int ncid = *(const int *)data;
    int *numgrps = (int *)(data + sizeof(int));
    int *grpids = (int *)(data + 2 * sizeof(int));

    // Call the function under test
    nc_inq_grps(ncid, numgrps, grpids);

    return 0;
}