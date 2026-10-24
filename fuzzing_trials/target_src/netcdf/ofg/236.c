#include <stdint.h>
#include <stddef.h>

// Function-under-test
int nc_close(int fd);

int LLVMFuzzerTestOneInput_236(const uint8_t *data, size_t size) {
    // Ensure that size is at least 1 to extract an integer value
    if (size < sizeof(int)) {
        return 0;
    }

    // Extract an integer from the input data
    int fd = *(int *)data;

    // Call the function-under-test
    nc_close(fd);

    return 0;
}