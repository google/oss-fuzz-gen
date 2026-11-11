#include <stdint.h>
#include <stddef.h>

// Function prototype for the function-under-test
int nc_inq_var_deflate(int ncid, int varid, int *shufflep, int *deflatep, int *deflate_levelp);

int LLVMFuzzerTestOneInput_33(const uint8_t *data, size_t size) {
    // Ensure that the input size is sufficient for the parameters
    if (size < sizeof(int) * 2) {
        return 0;
    }

    // Extract integers from the input data
    int ncid = *((int*)data);
    int varid = *((int*)(data + sizeof(int)));

    // Declare and initialize the pointers for the output parameters
    int shuffle = 0;
    int deflate = 0;
    int deflate_level = 0;

    // Call the function-under-test
    nc_inq_var_deflate(ncid, varid, &shuffle, &deflate, &deflate_level);

    return 0;
}