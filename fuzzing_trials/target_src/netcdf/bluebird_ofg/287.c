#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "netcdf.h"

int LLVMFuzzerTestOneInput_287(const uint8_t *data, size_t size) {
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

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from nc_open_mem to nc_put_vara_double
    const char jwfynadq[1024] = "duwck";
    int ret_nc_delete_imtra = nc_delete(jwfynadq);
    if (ret_nc_delete_imtra < 0){
    	return 0;
    }
    int ret_nc_abort_uecbd = nc_abort(NC_EDIMMETA);
    if (ret_nc_abort_uecbd < 0){
    	return 0;
    }

    int ret_nc_put_vara_double_goiik = nc_put_vara_double(NC_ENODATA, NC_UINT, (const size_t *)&ret_nc_delete_imtra, (const size_t *)&ncid, (const double *)&ret_nc_abort_uecbd);
    if (ret_nc_put_vara_double_goiik < 0){
    	return 0;
    }

    // End mutation: Producer.APPEND_MUTATOR

    free(memory);

    return 0;
}