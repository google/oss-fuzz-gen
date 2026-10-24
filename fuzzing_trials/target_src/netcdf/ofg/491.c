#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

// Function prototype for the function-under-test
int nc_put_var1_schar(int ncid, int varid, const size_t *indexp, const signed char *op);

// Fuzzer entry point
int LLVMFuzzerTestOneInput_491(const uint8_t *data, size_t size) {
    // Ensure there's enough data for the parameters
    if (size < sizeof(int) * 2 + sizeof(size_t) + sizeof(signed char)) {
        return 0;
    }

    // Extract parameters from the input data
    int ncid = *(const int *)(data);
    int varid = *(const int *)(data + sizeof(int));
    size_t index = *(const size_t *)(data + sizeof(int) * 2);
    signed char op = *(const signed char *)(data + sizeof(int) * 2 + sizeof(size_t));

    // Call the function-under-test
    nc_put_var1_schar(ncid, varid, &index, &op);

    return 0;
}