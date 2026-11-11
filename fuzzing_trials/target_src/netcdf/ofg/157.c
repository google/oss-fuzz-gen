#include <stdint.h>
#include <stddef.h>
#include <netcdf.h>

// Function prototype for nctypelen, assuming it is defined elsewhere
int nctypelen(nc_type type);

int LLVMFuzzerTestOneInput_157(const uint8_t *data, size_t size) {
    // Ensure we have enough data to interpret as an nc_type
    if (size < sizeof(nc_type)) {
        return 0;
    }

    // Interpret the first bytes of data as an nc_type
    nc_type type = *(const nc_type *)data;

    // Call the function-under-test
    int length = nctypelen(type);

    // Use the result in some way to avoid any compiler optimizations
    (void)length;

    return 0;
}