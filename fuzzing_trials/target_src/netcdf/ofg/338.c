#include <stdint.h>
#include <stddef.h>

// Assume the function is declared in some header file
int nc_get_var_schar(int arg1, int arg2, signed char *arg3);

int LLVMFuzzerTestOneInput_338(const uint8_t *data, size_t size) {
    // Ensure there is enough data to extract two integers
    if (size < sizeof(int) * 2 + sizeof(signed char)) {
        return 0;
    }

    // Extract two integers from the data
    int arg1 = *(const int *)data;
    int arg2 = *(const int *)(data + sizeof(int));

    // Allocate memory for a signed char
    signed char arg3;
    
    // Call the function-under-test
    nc_get_var_schar(arg1, arg2, &arg3);

    return 0;
}