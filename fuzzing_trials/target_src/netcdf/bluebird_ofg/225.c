#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

// Assuming the function is declared in a header file
int nc_get_var1_uchar(int ncid, int varid, const size_t *indexp, unsigned char *ip);

int LLVMFuzzerTestOneInput_225(const uint8_t *data, size_t size) {
    // Ensure the input size is large enough to extract required parameters
    if (size < sizeof(int) * 2 + sizeof(size_t)) {
        return 0;
    }

    // Extract parameters from the data
    int ncid = *(const int *)(data);
    int varid = *(const int *)(data + sizeof(int));
    size_t index = *(const size_t *)(data + sizeof(int) * 2);

    // Allocate memory for the output parameter
    unsigned char *ip = (unsigned char *)malloc(sizeof(unsigned char));
    if (ip == NULL) {
        return 0; // If allocation fails, return
    }

    // Call the function-under-test
    nc_get_var1_uchar(ncid, varid, &index, ip);

    // Free allocated memory
    free(ip);

    return 0;
}