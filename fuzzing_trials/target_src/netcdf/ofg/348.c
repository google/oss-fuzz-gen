#include <stdint.h>
#include <stddef.h>
#include <netcdf.h>

int LLVMFuzzerTestOneInput_348(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient for our needs
    if (size < sizeof(int) * 2 + sizeof(nc_type) * 2) {
        return 0;
    }

    // Extract parameters from the input data
    int ncid1 = *(const int *)(data);
    nc_type xtype1 = *(const nc_type *)(data + sizeof(int));
    int ncid2 = *(const int *)(data + sizeof(int) + sizeof(nc_type));
    nc_type xtype2 = *(const nc_type *)(data + 2 * sizeof(int) + sizeof(nc_type));

    // Initialize the result variable
    int equal = 0;

    // Call the function-under-test
    nc_inq_type_equal(ncid1, xtype1, ncid2, xtype2, &equal);

    return 0;
}