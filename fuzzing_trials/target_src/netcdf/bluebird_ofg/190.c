#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "netcdf.h"

int LLVMFuzzerTestOneInput_190(const uint8_t *data, size_t size) {
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
    int ret_nctypelen_hxwfw = nctypelen(NC_QUANTIZE_GRANULARBR);
    if (ret_nctypelen_hxwfw < 0){
    	return 0;
    }


    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from nctypelen to nc_put_var_float
    int ret_nc_redef_labhs = nc_redef(ncid);
    if (ret_nc_redef_labhs < 0){
    	return 0;
    }

    int ret_nc_put_var_float_czuvq = nc_put_var_float(ret_nc_redef_labhs, NC_ENOPAR, (const float *)&ret_nctypelen_hxwfw);
    if (ret_nc_put_var_float_czuvq < 0){
    	return 0;
    }

    // End mutation: Producer.APPEND_MUTATOR

    int ret_nc_inq_path_icrby = nc_inq_path(NC_EUNLIMPOS, (size_t *)&ret_nctypelen_hxwfw, (char *)memory);
    if (ret_nc_inq_path_icrby < 0){
    	return 0;
    }

    // End mutation: Producer.APPEND_MUTATOR


    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from nc_inq_path to nc_copy_data

    int ret_nc_copy_data_bbdgs = nc_copy_data(NC_EMAXNAME, NC_EVARSIZE, memory, NC_ENOPAR, (void *)data);
    if (ret_nc_copy_data_bbdgs < 0){
    	return 0;
    }

    // End mutation: Producer.APPEND_MUTATOR

    free(memory);

    return 0;
}