#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <netcdf.h>

int LLVMFuzzerTestOneInput_230(const uint8_t *data, size_t size) {
    // Ensure the size is sufficient for the test
    if (size < sizeof(int) + sizeof(nc_type) + sizeof(size_t)) {
        return 0;
    }

    // Extract the integer and nc_type from the input data
    int int_param = *(int *)data;
    nc_type type_param = *(nc_type *)(data + sizeof(int));

    // Calculate the remaining size for the void pointer data
    size_t void_data_size = size - sizeof(int) - sizeof(nc_type);

    // Allocate memory for the void pointer data
    void *void_data = malloc(void_data_size);
    if (!void_data) {
        return 0;
    }

    // Copy the remaining data into the allocated memory
    memcpy(void_data, data + sizeof(int) + sizeof(nc_type), void_data_size);

    // Call the function-under-test
    nc_reclaim_data_all(int_param, type_param, void_data, void_data_size);

    // Free the allocated memory
    free(void_data);

    return 0;
}