#include <stddef.h>
#include <stdint.h>

// Function-under-test declaration
int nc_get_var1_schar(int ncid, int varid, const size_t *indexp, signed char *valuep);

int LLVMFuzzerTestOneInput_224(const uint8_t *data, size_t size) {
    // Ensure there is enough data to extract meaningful values
    if (size < sizeof(int) * 2 + sizeof(size_t) + sizeof(signed char)) {
        return 0;
    }

    // Extract values for ncid and varid from the input data
    int ncid = *(int *)(data);
    int varid = *(int *)(data + sizeof(int));

    // Extract indexp from the input data
    const size_t *indexp = (const size_t *)(data + sizeof(int) * 2);

    // Extract valuep from the input data
    signed char *valuep = (signed char *)(data + sizeof(int) * 2 + sizeof(size_t));

    // Call the function-under-test
    nc_get_var1_schar(ncid, varid, indexp, valuep);

    return 0;
}