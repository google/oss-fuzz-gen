#include <stdint.h>
#include <stddef.h>
#include <stdio.h>  // Include for debugging output

#ifdef __cplusplus
extern "C" {
#endif

// Mock function for demonstration purposes
int nc_get_var_ubyte_98(int ncid, int varid, unsigned char *op) {
    // Simulate a simple operation based on input parameters
    if (ncid < 0 || varid < 0 || op == NULL) {
        return -1; // Return error for invalid parameters
    }

    // Perform a dummy operation
    *op = (unsigned char)((ncid + varid) % 256);

    // Print debug information to track coverage
    printf("ncid: %d, varid: %d, op: %u\n", ncid, varid, *op);

    return 0; // Return success
}

int LLVMFuzzerTestOneInput_98(const uint8_t *data, size_t size) {
    // Ensure there is enough data to extract parameters
    if (size < sizeof(int) * 2 + sizeof(unsigned char)) {
        return 0;
    }

    // Extract parameters from the input data
    int ncid = *((int *)data);
    int varid = *((int *)(data + sizeof(int)));
    unsigned char op_val = *(data + 2 * sizeof(int));

    // Prepare the output parameter
    unsigned char op = op_val;

    // Call the function-under-test
    nc_get_var_ubyte_98(ncid, varid, &op);

    return 0;
}

#ifdef __cplusplus
}
#endif