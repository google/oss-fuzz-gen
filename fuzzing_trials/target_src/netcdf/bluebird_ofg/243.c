#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>

// Mocking the function signature for demonstration purposes.
// In actual implementation, include the appropriate header file where the function is declared.
int nc_get_var_longlong(int param1, int param2, long long *param3);

int LLVMFuzzerTestOneInput_243(const uint8_t *data, size_t size) {
    // Ensure size is sufficient for extracting two integers and a long long
    if (size < sizeof(int) * 2 + sizeof(long long)) {
        return 0;
    }

    // Extract the first integer from data
    int param1 = *(int *)data;
    data += sizeof(int);
    size -= sizeof(int);

    // Extract the second integer from data
    int param2 = *(int *)data;
    data += sizeof(int);
    size -= sizeof(int);

    // Allocate memory for a long long variable
    long long result;
    long long *param3 = &result;

    // Call the function-under-test
    int ret = nc_get_var_longlong(param1, param2, param3);

    // Optionally, use the return value 'ret' or the dereferenced value '*param3' for further checks

    return 0;
}