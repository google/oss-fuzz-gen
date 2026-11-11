#include <stdint.h>
#include <stddef.h>

// Assuming the function is declared in some header file
int nc_get_var1_ulonglong(int ncid, int varid, const size_t *indexp, unsigned long long *ip);

int LLVMFuzzerTestOneInput_296(const uint8_t *data, size_t size) {
    // Declare and initialize variables for the function-under-test
    int ncid = 1;  // Example non-zero value
    int varid = 2; // Example non-zero value

    // Ensure the size is sufficient for the index array
    if (size < sizeof(size_t)) {
        return 0;
    }

    // Use the data as an index
    const size_t *indexp = (const size_t *)data;

    // Initialize the output variable
    unsigned long long output = 0;

    // Call the function-under-test
    nc_get_var1_ulonglong(ncid, varid, indexp, &output);

    return 0;
}