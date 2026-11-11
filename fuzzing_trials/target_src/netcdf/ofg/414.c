#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netcdf.h>

int LLVMFuzzerTestOneInput_414(const uint8_t *data, size_t size) {
    // Ensure there is enough data to extract parameters
    if (size < sizeof(int) * 2 + sizeof(size_t) * 2 + sizeof(unsigned int)) {
        return 0;
    }

    // Extract the integer parameters
    int param1 = *(int *)data;
    int param2 = *(int *)(data + sizeof(int));

    // Extract the size_t parameters
    const size_t *start = (const size_t *)(data + sizeof(int) * 2);
    const size_t *count = (const size_t *)(data + sizeof(int) * 2 + sizeof(size_t));

    // Extract the unsigned int parameter
    const unsigned int *value = (const unsigned int *)(data + sizeof(int) * 2 + sizeof(size_t) * 2);

    // Call the function-under-test
    int result = nc_put_vara_uint(param1, param2, start, count, value);

    // Print the result (for debugging purposes)
    printf("Result: %d\n", result);

    return 0;
}