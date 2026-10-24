#include <stdint.h>
#include <stddef.h>
#include <netcdf.h>

int LLVMFuzzerTestOneInput_532(const uint8_t *data, size_t size) {
    // Ensure there is enough data for the parameters
    if (size < sizeof(int) * 2 + sizeof(unsigned short)) {
        return 0;
    }

    // Extract the first int parameter
    int param1 = *(const int *)data;
    data += sizeof(int);
    size -= sizeof(int);

    // Extract the second int parameter
    int param2 = *(const int *)data;
    data += sizeof(int);
    size -= sizeof(int);

    // Prepare the unsigned short array
    const unsigned short *ushort_array = (const unsigned short *)data;
    size_t ushort_array_size = size / sizeof(unsigned short);

    // Call the function-under-test
    int result = nc_put_var_ushort(param1, param2, ushort_array);

    // Use result (if necessary) or just return
    return 0;
}