#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

// Assuming the function is declared in some header file
int nc_get_var_long(int, int, long *);

int LLVMFuzzerTestOneInput_249(const uint8_t *data, size_t size) {
    // Ensure the size is sufficient to extract two integers and a long
    if (size < sizeof(int) * 2 + sizeof(long)) {
        return 0;
    }

    // Extract two integers and a long from the data
    int param1 = *((int *)data);
    int param2 = *((int *)(data + sizeof(int)));
    long param3 = *((long *)(data + sizeof(int) * 2));

    // Call the function with the extracted parameters
    nc_get_var_long(param1, param2, &param3);

    return 0;
}