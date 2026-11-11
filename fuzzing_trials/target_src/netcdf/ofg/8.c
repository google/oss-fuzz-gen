#include <stdint.h>
#include <stddef.h>

// Assume the function is defined in some library
int nc_get_var_short(int arg1, int arg2, short *arg3);

int LLVMFuzzerTestOneInput_8(const uint8_t *data, size_t size) {
    // Ensure there is enough data to extract three integers
    if (size < sizeof(int) * 2 + sizeof(short)) {
        return 0;
    }

    // Extract the first integer from the data
    int arg1 = *(const int *)(data);
    
    // Extract the second integer from the data
    int arg2 = *(const int *)(data + sizeof(int));
    
    // Extract the short from the data
    short arg3;
    arg3 = *(const short *)(data + sizeof(int) * 2);

    // Call the function-under-test
    nc_get_var_short(arg1, arg2, &arg3);

    return 0;
}