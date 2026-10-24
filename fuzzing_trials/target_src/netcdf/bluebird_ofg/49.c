#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include "netcdf.h"
#include "netcdf_mem.h" // Include the header for NC_memio and nc_close_memio

int LLVMFuzzerTestOneInput_49(const uint8_t *data, size_t size) {
    // Ensure size is sufficient for creating a valid NC_memio structure
    if (size < sizeof(NC_memio)) {
        return 0;
    }

    // Initialize a NC_memio structure
    NC_memio memio;
    memio.size = size;
    memio.memory = (void *)data; // Cast data to void* for memory field
    memio.flags = 0; // Initialize flags to 0

    // Define a non-zero file ID
    int file_id = 1;

    // Call the function-under-test
    int result = nc_close_memio(file_id, &memio);

    // Return 0 to indicate the fuzzer can continue
    return 0;
}