#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

// Assume the function is declared in some header file
int nc_inq_grpname_len(int, size_t *);

int LLVMFuzzerTestOneInput_205(const uint8_t *data, size_t size) {
    // Ensure size is sufficient for our needs
    if (size < sizeof(int) + sizeof(size_t)) {
        return 0;
    }

    // Extract an int value from the input data
    int int_value = *(const int *)data;

    // Move the data pointer forward by the size of int
    data += sizeof(int);

    // Extract a size_t value from the input data
    size_t size_value = *(const size_t *)data;

    // Call the function-under-test
    int result = nc_inq_grpname_len(int_value, &size_value);

    // Use the result in some way to avoid compiler optimizations
    (void)result;

    return 0;
}