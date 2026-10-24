#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <netcdf.h>

int LLVMFuzzerTestOneInput_451(const uint8_t *data, size_t size) {
    int ncid = 0; // Assuming a valid netCDF ID for testing purposes
    nc_type type = NC_INT; // Assuming NC_INT type for testing purposes
    void *value = NULL;
    size_t len = 0;

    // Ensure there is enough data to read
    if (size < sizeof(int) + sizeof(nc_type) + sizeof(size_t)) {
        return 0;
    }

    // Extract ncid from data
    memcpy(&ncid, data, sizeof(int));
    data += sizeof(int);
    size -= sizeof(int);

    // Extract nc_type from data
    memcpy(&type, data, sizeof(nc_type));
    data += sizeof(nc_type);
    size -= sizeof(nc_type);

    // Extract length from data
    memcpy(&len, data, sizeof(size_t));
    data += sizeof(size_t);
    size -= sizeof(size_t);

    // Allocate memory for value based on the remaining data size
    if (size > 0) {
        value = malloc(size);
        if (value != NULL) {
            memcpy(value, data, size);
        }
    }

    // Call the function-under-test
    nc_reclaim_data(ncid, type, value, len);

    // Free allocated memory
    if (value != NULL) {
        free(value);
    }

    return 0;
}