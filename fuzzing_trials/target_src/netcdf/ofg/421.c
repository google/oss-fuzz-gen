#include <stdint.h>
#include <stddef.h>
#include <netcdf.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput_421(const uint8_t *data, size_t size) {
    // Ensure that size is sufficient to extract necessary parameters
    if (size < sizeof(int) + 1) {
        return 0;
    }

    // Extract an integer from the data
    int ncid = *(const int *)data;
    data += sizeof(int);
    size -= sizeof(int);

    // Use the remaining data as a string for the variable name
    // Ensure the string is null-terminated
    char var_name[size + 1];
    memcpy(var_name, data, size);
    var_name[size] = '\0';

    // Allocate space for the variable ID
    int varid;

    // Call the function-under-test
    nc_inq_varid(ncid, var_name, &varid);

    return 0;
}