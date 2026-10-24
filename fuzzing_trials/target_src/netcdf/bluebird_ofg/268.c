#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "netcdf.h"

int LLVMFuzzerTestOneInput_268(const uint8_t *data, size_t size) {
    // Define and initialize parameters for nc_open_mem
    const char *path = "fuzz_mem.nc"; // A non-NULL string for the file name
    int mode = NC_NOWRITE; // A valid mode for opening a netCDF file
    size_t mem_size = size; // Use the size of the input data
    void *memory = malloc(mem_size); // Allocate memory for the file content
    int ncid; // Variable to store the netCDF ID

    if (memory == NULL) {
        return 0; // Exit if memory allocation fails
    }

    // Copy the input data to the allocated memory
    memcpy(memory, data, mem_size);

    // Call the function-under-test
    nc_open_mem(path, mode, mem_size, memory, &ncid);

    // Free the allocated memory

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from nc_open_mem to nc_inq_path
    int ret_nc_sync_wolso = nc_sync(NC_EPLUGIN);
    if (ret_nc_sync_wolso < 0){
    	return 0;
    }
    int ret_nctypelen_aisfo = nctypelen(NC_ERANGE);
    if (ret_nctypelen_aisfo < 0){
    	return 0;
    }


    // Begin mutation: Producer.REPLACE_ARG_MUTATOR - Replaced argument 0 of nc_inq_path
    int ret_nc_inq_path_rclxu = nc_inq_path(NC_ECANTREMOVE, (size_t *)&ret_nctypelen_aisfo, (char *)memory);
    // End mutation: Producer.REPLACE_ARG_MUTATOR


    if (ret_nc_inq_path_rclxu < 0){
    	return 0;
    }

    // End mutation: Producer.APPEND_MUTATOR

    free(memory);

    return 0;
}