#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

extern int nc_get_vars(int, int, const size_t *, const size_t *, const ptrdiff_t *, void *);

int LLVMFuzzerTestOneInput_512(const uint8_t *data, size_t size) {
    // Ensure there's enough data to initialize all parameters
    if (size < sizeof(int) * 2 + sizeof(size_t) * 2 + sizeof(ptrdiff_t) + sizeof(void *)) {
        return 0;
    }

    // Initialize the parameters
    int param1 = (int)data[0];
    int param2 = (int)data[1];

    size_t start[1] = { (size_t)data[2] };
    size_t count[1] = { (size_t)data[3] };
    ptrdiff_t stride[1] = { (ptrdiff_t)data[4] };

    // Allocate a buffer for the void* parameter
    char buffer[10]; // Arbitrary size for demonstration
    void *param6 = (void *)buffer;

    // Call the function-under-test
    int result = nc_get_vars(param1, param2, start, count, stride, param6);

    // Optional: Print the result for debugging purposes
    printf("nc_get_vars returned: %d\n", result);

    return 0;
}