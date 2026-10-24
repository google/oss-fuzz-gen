#include <stdint.h>
#include <stddef.h>
#include "netcdf.h"

int LLVMFuzzerTestOneInput_202(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient for the parameters
    if (size < sizeof(int) * 2 + sizeof(signed char)) {
        return 0;
    }

    // Extract the parameters from the input data
    int param1 = *(const int *)(data);
    int param2 = *(const int *)(data + sizeof(int));
    const signed char *param3 = (const signed char *)(data + sizeof(int) * 2);

    // Call the function-under-test
    nc_put_var_schar(param1, param2, param3);

    return 0;
}