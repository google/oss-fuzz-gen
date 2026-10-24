#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "netcdf.h"

int LLVMFuzzerTestOneInput_53(const uint8_t *data, size_t size) {
    // Declare and initialize variables for the function-under-test
    int ncid = 1;  // Example non-zero netCDF file ID
    int varid = 1; // Example non-zero variable ID

    // Ensure there is enough data to extract a valid string and values
    if (size < 2) return 0;

    // Use the first byte of data to determine the length of the attribute name
    size_t attr_name_len = data[0] % (size - 1) + 1; // Ensure it's at least 1 and within bounds

    // Ensure there is enough data for the attribute name
    if (size < 1 + attr_name_len) return 0;

    // Extract the attribute name from the data
    char *attr_name = (char *)malloc(attr_name_len + 1);
    if (attr_name == NULL) return 0;
    memcpy(attr_name, data + 1, attr_name_len);
    attr_name[attr_name_len] = '\0'; // Null-terminate the string

    // Use the remaining data to determine the number of elements
    size_t num_elements = (size - 1 - attr_name_len) / sizeof(unsigned long long);
    if (num_elements == 0) {
        free(attr_name);
        return 0;
    }

    // Extract the unsigned long long values from the data
    const unsigned long long *values = (const unsigned long long *)(data + 1 + attr_name_len);

    // Call the function-under-test
    nc_put_att_ulonglong(ncid, varid, attr_name, NC_UINT64, num_elements, values);

    // Clean up
    free(attr_name);

    return 0;
}