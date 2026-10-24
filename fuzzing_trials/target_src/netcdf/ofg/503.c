#include <stdint.h>
#include <stddef.h>
#include <netcdf.h>

int LLVMFuzzerTestOneInput_503(const uint8_t *data, size_t size) {
    // Ensure that the size is sufficient to extract required parameters
    if (size < sizeof(int) * 3) {
        return 0;
    }

    // Extracting parameters from the input data
    int ncid = *(int *)(data);
    nc_type xtype = *(nc_type *)(data + sizeof(int));
    int fieldid = *(int *)(data + 2 * sizeof(int));

    // Initialize an array to store dimension sizes
    int dim_sizes[10]; // Assuming a maximum of 10 dimensions for fuzzing

    // Call the function-under-test
    int result = nc_inq_compound_fielddim_sizes(ncid, xtype, fieldid, dim_sizes);

    // Use the result to ensure the function call is complete
    (void)result;

    return 0;
}