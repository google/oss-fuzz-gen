#include <stddef.h>
#include <stdint.h>

// Function-under-test declaration
int nc__enddef(int, size_t, size_t, size_t, size_t);

int LLVMFuzzerTestOneInput_118(const uint8_t *data, size_t size) {
    // Declare and initialize variables for the parameters of nc__enddef
    int param1 = (size > 0) ? data[0] : 1; // Use input data if available
    size_t param2 = (size > 1) ? data[1] : 2; // Use input data if available
    size_t param3 = (size > 2) ? data[2] : 3; // Use input data if available
    size_t param4 = (size > 3) ? data[3] : 4; // Use input data if available
    size_t param5 = (size > 4) ? data[4] : 5; // Use input data if available

    // Call the function-under-test
    nc__enddef(param1, param2, param3, param4, param5);

    return 0;
}