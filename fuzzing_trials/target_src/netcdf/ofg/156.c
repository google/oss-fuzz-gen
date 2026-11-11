#include <stdint.h>
#include <stddef.h>
#include <netcdf.h>

// Function prototype for nctypelen to ensure it's declared
int nctypelen(nc_type type);

int LLVMFuzzerTestOneInput_156(const uint8_t *data, size_t size) {
    // Ensure there is enough data to extract a valid nc_type
    if (size < sizeof(nc_type)) {
        return 0;
    }

    // Extract an nc_type from the input data
    nc_type type = *((nc_type *)data);

    // Call the function-under-test
    int result = nctypelen(type);

    // Use the result in some way to prevent compiler optimizations from removing the call
    if (result < 0) {
        // Handle the error case (if any specific handling is needed)
    }

    return 0;
}