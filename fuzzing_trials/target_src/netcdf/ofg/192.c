#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>

// Mock implementation of the function-under-test
// This should be replaced with the actual function signature and implementation
int nc_inq_grp_parent_192(int ncid, int *parent_ncid) {
    // Example implementation for demonstration purposes
    if (parent_ncid == NULL) {
        return -1; // Simulating an error if parent_ncid is NULL
    }
    *parent_ncid = ncid + 1; // Simulate setting parent_ncid
    return 0; // Simulate success
}

int LLVMFuzzerTestOneInput_192(const uint8_t *data, size_t size) {
    // Ensure there's enough data to extract an integer
    if (size < sizeof(int)) {
        return 0;
    }

    // Extract an integer from the input data
    int ncid = *((int *)data);

    // Allocate memory for the parent_ncid
    int parent_ncid;
    
    // Call the function-under-test
    int result = nc_inq_grp_parent_192(ncid, &parent_ncid);

    // Optionally, print the result and parent_ncid for debugging
    printf("Result: %d, Parent NCID: %d\n", result, parent_ncid);

    return 0;
}