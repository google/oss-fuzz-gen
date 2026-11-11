#include <stddef.h>
#include <stdint.h>

// Include the necessary header for the function-under-test
#include <netcdf.h>

// Remove the 'extern "C"' linkage specification, as it is not valid in C code
int LLVMFuzzerTestOneInput_489(const uint8_t *data, size_t size) {
    // Ensure there's enough data to extract the required parameters
    if (size < sizeof(int) * 2 + sizeof(signed char)) {
        return 0;
    }

    // Extract parameters from the input data
    int param1 = *(const int *)(data);
    int param2 = *(const int *)(data + sizeof(int));
    const signed char *param3 = (const signed char *)(data + 2 * sizeof(int));

    // Call the function-under-test
    nc_put_var_schar(param1, param2, param3);

    return 0;
}