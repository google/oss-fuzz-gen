#include <stdint.h>
#include <stddef.h>

// Function-under-test
int nc_close(int fd);

int LLVMFuzzerTestOneInput_235(const uint8_t *data, size_t size) {
    // Ensure the size is sufficient to extract an integer
    if (size < sizeof(int)) {
        return 0;
    }

    // Extract an integer from the data
    int fd = *((int*)data);

    // Call the function-under-test
    nc_close(fd);

    return 0;
}