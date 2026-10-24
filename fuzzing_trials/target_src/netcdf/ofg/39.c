#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

// Assume the function is defined elsewhere
extern int nc_get_var1_int(int ncid, int varid, const size_t *indexp, int *ip);

int LLVMFuzzerTestOneInput_39(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient for our needs
    if (size < sizeof(size_t) + sizeof(int)) {
        return 0;
    }

    // Initialize parameters for nc_get_var1_int
    int ncid = (int)data[0]; // Use the first byte for ncid
    int varid = (int)data[1]; // Use the second byte for varid

    // Use the next part of the data for indexp
    const size_t *indexp = (const size_t *)(data + 2);

    // Allocate memory for ip and ensure it is not NULL
    int *ip = (int *)malloc(sizeof(int));
    if (ip == NULL) {
        return 0;
    }

    // Call the function-under-test
    nc_get_var1_int(ncid, varid, indexp, ip);

    // Free allocated memory
    free(ip);

    return 0;
}