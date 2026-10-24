#include <stdint.h>
#include <stddef.h>
#include <netcdf.h>
#include <stdlib.h>

int LLVMFuzzerTestOneInput_50(const uint8_t *data, size_t size) {
    // Ensure there is enough data for the parameters
    if (size < sizeof(int) * 2 + sizeof(long long)) {
        return 0;
    }

    // Extract the first integer parameter
    int param1 = *((int*)data);
    data += sizeof(int);
    size -= sizeof(int);

    // Extract the second integer parameter
    int param2 = *((int*)data);
    data += sizeof(int);
    size -= sizeof(int);

    // Extract the long long parameter
    const long long *param3 = (const long long*)data;

    // Call the function-under-test
    nc_put_var_longlong(param1, param2, param3);

    return 0;
}