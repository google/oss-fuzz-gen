#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <netcdf.h>

int LLVMFuzzerTestOneInput_454(const uint8_t *data, size_t size) {
    // Ensure the data is large enough to extract necessary parameters
    if (size < 3) return 0;

    // Extract parameters from the data
    int ncid = data[0]; // First byte as ncid
    int varid = data[1]; // Second byte as varid

    // Remaining data as the attribute name, ensure null-termination
    size_t attr_name_len = size - 2;
    char *attr_name = (char *)malloc(attr_name_len + 1);
    if (attr_name == NULL) return 0;
    memcpy(attr_name, data + 2, attr_name_len);
    attr_name[attr_name_len] = '\0';

    // Allocate memory for attlen
    size_t attlen;
    
    // Call the function-under-test
    nc_inq_attlen(ncid, varid, attr_name, &attlen);

    // Clean up
    free(attr_name);

    return 0;
}