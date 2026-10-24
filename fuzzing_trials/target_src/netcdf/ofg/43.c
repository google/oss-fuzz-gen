#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <netcdf.h>

int LLVMFuzzerTestOneInput_43(const uint8_t *data, size_t size) {
    // Ensure the input size is large enough to extract necessary values
    if (size < sizeof(int) * 2 + sizeof(size_t) * 2 + sizeof(ptrdiff_t) + sizeof(unsigned short)) {
        return 0;
    }

    // Extract values from the data
    const int *int_data = (const int *)data;
    int ncid = int_data[0];
    int varid = int_data[1];

    const size_t *size_t_data = (const size_t *)(data + sizeof(int) * 2);
    size_t start = size_t_data[0];
    size_t count = size_t_data[1];

    const ptrdiff_t *ptrdiff_data = (const ptrdiff_t *)(data + sizeof(int) * 2 + sizeof(size_t) * 2);
    ptrdiff_t stride = ptrdiff_data[0];

    const unsigned short *ushort_data = (const unsigned short *)(data + sizeof(int) * 2 + sizeof(size_t) * 2 + sizeof(ptrdiff_t));
    unsigned short value = ushort_data[0];

    // Prepare arrays for the function call
    size_t start_arr[1] = {start};
    size_t count_arr[1] = {count};
    ptrdiff_t stride_arr[1] = {stride};
    unsigned short value_arr[1] = {value};

    // Call the function-under-test
    nc_put_vars_ushort(ncid, varid, start_arr, count_arr, stride_arr, value_arr);

    return 0;
}