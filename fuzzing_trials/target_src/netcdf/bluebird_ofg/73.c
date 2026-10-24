#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "netcdf.h"

int LLVMFuzzerTestOneInput_73(const uint8_t *data, size_t size) {
    // Ensure the data is large enough to extract meaningful values
    if (size < 10) {
        return 0;
    }

    // Extract values from the data
    int ncid = (int)data[0];
    int varid = (int)data[1];

    // Allocate memory for the attribute name and ensure it's null-terminated
    char attname[5];
    memcpy(attname, data + 2, 4);
    attname[4] = '\0'; // Null-terminate the string

    // Prepare the nc_type and size_t variables
    nc_type xtype;
    size_t attlen;

    // Call the function-under-test
    int result = nc_inq_att(ncid, varid, attname, &xtype, &attlen);

    // Return 0 as the fuzzer expects
    return 0;
}