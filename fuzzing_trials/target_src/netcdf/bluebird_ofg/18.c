#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h> // Include string.h for memcpy
#include "netcdf.h"

int LLVMFuzzerTestOneInput_18(const uint8_t *data, size_t size) {
    int ncid = 1; // Example non-zero integer, assuming a valid ncid for testing
    nc_type xtype = NC_INT; // Example nc_type, assuming NC_INT is valid for testing
    void *memory = malloc(size); // Allocate memory for the void pointer
    if (memory == NULL) {
        return 0; // Exit if memory allocation fails
    }

    // Copy the input data to the allocated memory
    if (size > 0) {
        memcpy(memory, data, size);
    }

    // Call the function-under-test
    int retval = nc_reclaim_data_all(ncid, xtype, memory, size);

    // Check if nc_reclaim_data_all was successful before freeing memory
    if (retval != NC_NOERR) {
        // Handle error if necessary
        free(memory);
        return 0;
    }

    // If nc_reclaim_data_all manages the memory, do not free it again
    // Assuming nc_reclaim_data_all manages the memory if it returns NC_NOERR
    // Commenting out the free(memory) to avoid double-free
    // free(memory);

    return 0;
}