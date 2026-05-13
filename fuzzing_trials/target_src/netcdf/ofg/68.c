#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <netcdf.h>

int LLVMFuzzerTestOneInput_68(const uint8_t *data, size_t size) {
    // Ensure that the input data is large enough to extract necessary parameters
    if (size < 4) {
        return 0;
    }

    // Extracting parameters from the input data
    int ncid = (int)data[0];  // Assuming the first byte is used for ncid
    int varid = (int)data[1]; // Assuming the second byte is used for varid
    size_t name_len = (size_t)data[2]; // Assuming the third byte is used for name length

    // Ensure that name_len does not exceed the remaining size
    if (name_len > size - 3) {
        return 0;
    }

    // Extracting the name from the input data
    char *name = (char *)malloc(name_len + 1);
    if (name == NULL) {
        return 0;
    }
    memcpy(name, &data[3], name_len);
    name[name_len] = '\0'; // Null-terminate the string

    // Allocate memory for the double attribute
    double attr_value;
    
    // Call the function-under-test
    nc_get_att_double(ncid, varid, name, &attr_value);

    // Free allocated memory
    free(name);

    return 0;
}