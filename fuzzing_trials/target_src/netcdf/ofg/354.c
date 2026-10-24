#include <stdint.h>
#include <stdlib.h>
#include <netcdf.h>     // Include the main NetCDF header first
#include <netcdf_mem.h> // Include the header that defines NC_memio

// Function prototype for nc_close_memio if it's not included by default
// This should be removed if nc_close_memio is declared in netcdf_mem.h
int nc_close_memio(int ncid, NC_memio *memio);

int LLVMFuzzerTestOneInput_354(const uint8_t *data, size_t size) {
    // Ensure we have enough data to work with
    if (size < sizeof(int) + sizeof(NC_memio)) {
        return 0;
    }

    // Initialize the first part of the data as an integer
    int ncid = *(int *)data;

    // Allocate memory for NC_memio and initialize it
    NC_memio *memio = (NC_memio *)malloc(sizeof(NC_memio));
    if (memio == NULL) {
        return 0;
    }

    // Initialize the NC_memio structure with non-NULL values
    memio->size = size - sizeof(int);
    memio->memory = (void *)(data + sizeof(int));

    // Call the function-under-test
    int result = nc_close_memio(ncid, memio);

    // Free allocated memory
    free(memio);

    return 0;
}