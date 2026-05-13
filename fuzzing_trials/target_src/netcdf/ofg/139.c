#include <stdint.h>
#include <stddef.h>

// Assuming the function is defined elsewhere
extern int nc_get_alignment(int *align1, int *align2);

int LLVMFuzzerTestOneInput_139(const uint8_t *data, size_t size) {
    // Check if the input size is sufficient to extract two integers
    if (size < sizeof(int) * 2) {
        return 0;
    }

    // Initialize two integer pointers with values from the data
    int align1 = *((int*)data);
    int align2 = *((int*)(data + sizeof(int)));

    // Call the function-under-test
    int result = nc_get_alignment(&align1, &align2);

    // Use the result in some way to avoid compiler optimizations removing the call
    (void)result;

    return 0;
}