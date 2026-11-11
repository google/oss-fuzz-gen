#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <netcdf.h>

int LLVMFuzzerTestOneInput_461(const uint8_t *data, size_t size) {
    // Ensure the data size is sufficient for the inputs
    if (size < sizeof(int) + 1) {
        return 0;
    }

    // Extract an integer from the data
    int ncid = *(const int *)data;
    data += sizeof(int);
    size -= sizeof(int);

    // Create a null-terminated string from the remaining data
    char *name = (char *)malloc(size + 1);
    if (name == NULL) {
        return 0;
    }
    memcpy(name, data, size);
    name[size] = '\0';

    // Prepare the output parameter
    int grp_ncid;

    // Call the function under test
    nc_inq_grp_full_ncid(ncid, name, &grp_ncid);

    // Clean up
    free(name);

    return 0;
}