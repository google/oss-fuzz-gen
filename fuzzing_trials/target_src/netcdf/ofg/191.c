#include <stdint.h>
#include <stddef.h>

// Assuming the function is declared in some header file
extern int nc_inq_grp_parent(int, int *);

int LLVMFuzzerTestOneInput_191(const uint8_t *data, size_t size) {
    // Ensure size is sufficient to extract two integers
    if (size < 2 * sizeof(int)) {
        return 0;
    }

    // Extract two integers from the input data
    int arg1 = *((int *)data);
    int arg2;

    // Call the function-under-test
    int result = nc_inq_grp_parent(arg1, &arg2);

    // Use the result and arg2 in some way to avoid compiler optimizations
    (void)result;
    (void)arg2;

    return 0;
}