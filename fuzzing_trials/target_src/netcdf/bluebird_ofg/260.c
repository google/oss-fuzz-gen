#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

extern int nc_get_vara_ubyte(int ncid, int varid, const size_t *start, const size_t *count, unsigned char *value);

int LLVMFuzzerTestOneInput_260(const uint8_t *data, size_t size) {
    // Ensure there's enough data to extract meaningful values
    if (size < 4 * sizeof(size_t) + sizeof(unsigned char)) {
        return 0;
    }

    // Extract values from data
    int ncid = (int)data[0];
    int varid = (int)data[1];
    
    // Define and initialize start and count arrays
    size_t start[2];
    size_t count[2];
    
    start[0] = (size_t)data[2];
    start[1] = (size_t)data[3];
    
    count[0] = (size_t)data[4];
    count[1] = (size_t)data[5];

    // Allocate memory for value array
    unsigned char *value = (unsigned char *)malloc(count[0] * count[1] * sizeof(unsigned char));
    if (value == NULL) {
        return 0;
    }

    // Call the function-under-test
    nc_get_vara_ubyte(ncid, varid, start, count, value);

    // Free allocated memory
    free(value);

    return 0;
}