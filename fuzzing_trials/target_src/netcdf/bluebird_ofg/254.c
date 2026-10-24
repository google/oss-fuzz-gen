#include <stdint.h>
#include <stddef.h>

// Assume this is the function-under-test
int nc_get_var(int param1, int param2, void *param3);

int LLVMFuzzerTestOneInput_254(const uint8_t *data, size_t size) {
    // Ensure size is sufficient for our needs
    if (size < sizeof(int) * 2 + 1) {
        return 0;
    }

    // Extract the first two integers from the input data
    int param1 = *((int *)data);
    int param2 = *((int *)(data + sizeof(int)));

    // Use the remaining data as the void pointer
    void *param3 = (void *)(data + sizeof(int) * 2);

    // Call the function-under-test
    nc_get_var(param1, param2, param3);

    return 0;
}