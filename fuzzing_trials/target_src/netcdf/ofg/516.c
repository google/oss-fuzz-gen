#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <netcdf.h>

int LLVMFuzzerTestOneInput_516(const uint8_t *data, size_t size) {
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
    free(memory);

    return 0;
}