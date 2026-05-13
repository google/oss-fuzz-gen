#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

// Assume the function is declared in a header file
extern int nc_inq_grpname_len(int, size_t *);

int LLVMFuzzerTestOneInput_35(const uint8_t *data, size_t size) {
    // Ensure the data size is sufficient to extract an integer
    if (size < sizeof(int)) {
        return 0;
    }

    // Extract an integer from the input data
    int grp_id = *(const int *)data;

    // Create a size_t variable to pass to the function
    size_t grpname_len;

    // Call the function-under-test
    int result = nc_inq_grpname_len(grp_id, &grpname_len);

    // Use the result and grpname_len to prevent compiler optimizations
    (void)result;
    (void)grpname_len;

    return 0;
}