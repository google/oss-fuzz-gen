#include <stdint.h>
#include <stddef.h>

// Assuming the function nc_enddef is defined elsewhere, we declare it here.
int nc_enddef(int);

int LLVMFuzzerTestOneInput_94(const uint8_t *data, size_t size) {
    // Declare and initialize the parameter for nc_enddef
    int param = 0;

    // Ensure size is sufficient to extract an integer
    if (size >= sizeof(int)) {
        // Use the first bytes of data to form an integer for the parameter
        param = *(int *)data;
    }

    // Call the function-under-test
    nc_enddef(param);

    return 0;
}