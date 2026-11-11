#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

extern int nc_get_vars_text(int ncid, int varid, const size_t *start, const size_t *count, const ptrdiff_t *stride, char *data);

int LLVMFuzzerTestOneInput_156(const uint8_t *data, size_t size) {
    // Define variables for the function parameters
    int ncid = 1;
    int varid = 1;
    size_t start[3] = {0, 0, 0};
    size_t count[3] = {1, 1, 1};
    ptrdiff_t stride[3] = {1, 1, 1};
    
    // Ensure there is enough data to fill the buffer
    size_t dataSize = 3;
    char *buffer = (char *)malloc(dataSize);
    if (buffer == NULL) {
        return 0;
    }

    // Copy data into buffer, ensuring not to exceed buffer size
    size_t copySize = size < dataSize ? size : dataSize;
    memcpy(buffer, data, copySize);

    // Call the function-under-test
    nc_get_vars_text(ncid, varid, start, count, stride, buffer);

    // Clean up
    free(buffer);

    return 0;
}