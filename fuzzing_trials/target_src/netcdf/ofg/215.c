#include <stdint.h>
#include <stddef.h>

// Assuming the function is declared in some header file
// int nc_get_var_ulonglong(int, int, unsigned long long *);

int LLVMFuzzerTestOneInput_215(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient to extract the required parameters
    if (size < sizeof(int) * 2 + sizeof(unsigned long long)) {
        return 0;
    }

    // Extract the parameters from the input data
    int param1 = *(int *)(data);
    int param2 = *(int *)(data + sizeof(int));
    unsigned long long result;

    // Call the function-under-test
    nc_get_var_ulonglong(param1, param2, &result);

    return 0;
}