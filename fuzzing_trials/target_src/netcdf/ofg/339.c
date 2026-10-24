#include <stdint.h>
#include <stdlib.h>

// Assume the function is declared in an external library
extern int nc_get_var_schar(int param1, int param2, signed char *param3);

int LLVMFuzzerTestOneInput_339(const uint8_t *data, size_t size) {
    // Ensure the size is large enough to extract two integers and a signed char
    if (size < sizeof(int) * 2 + sizeof(signed char)) {
        return 0;
    }

    // Extract two integers from the input data
    int param1 = *(int *)(data);
    int param2 = *(int *)(data + sizeof(int));

    // Allocate a signed char and initialize it with a value from the input data
    signed char param3 = *(signed char *)(data + sizeof(int) * 2);

    // Call the function-under-test
    nc_get_var_schar(param1, param2, &param3);

    return 0;
}