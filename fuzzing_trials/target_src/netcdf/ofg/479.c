#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include "netcdf.h" // Assuming this is the header where nc_copy_data_all is declared

int LLVMFuzzerTestOneInput_479(const uint8_t *data, size_t size) {
    // Define and initialize the parameters for nc_copy_data_all
    int param1 = 1; // Assuming a valid integer value for the first parameter
    nc_type param2 = NC_INT; // Assuming NC_INT is a valid nc_type
    const void *param3 = data; // Use the provided data as the third parameter
    size_t param4 = size; // Use the size of the data as the fourth parameter
    void *param5 = malloc(size); // Allocate memory for the fifth parameter

    // Ensure param5 is not NULL
    if (param5 == NULL) {
        return 0; // Exit if memory allocation fails
    }

    // Call the function-under-test
    int result = nc_copy_data_all(param1, param2, param3, param4, &param5);

    // Free the allocated memory
    free(param5);

    return 0;
}