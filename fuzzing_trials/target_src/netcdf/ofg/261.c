#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>

// Function-under-test declaration
int nc_inq_typeids(int ncid, int *ntypes, int *typeids);

int LLVMFuzzerTestOneInput_261(const uint8_t *data, size_t size) {
    // Ensure there is enough data to extract integers
    if (size < sizeof(int) * 3) {
        return 0;
    }

    // Extract integers from the input data
    int ncid = *(int *)(data);
    int ntypes = *(int *)(data + sizeof(int));
    int typeidsBuffer[10]; // Assuming a maximum of 10 type IDs for demonstration
    int *typeids = typeidsBuffer;

    // Call the function-under-test
    int result = nc_inq_typeids(ncid, &ntypes, typeids);

    // Use the result in some way to prevent compiler optimizations from removing the call
    (void)result;

    return 0;
}