#include <stdint.h>
#include <stddef.h>

// Assuming the function is declared somewhere in the included headers
int nc_def_var_quantize(int ncid, int varid, int quantize_mode, int nsd);

int LLVMFuzzerTestOneInput_185(const uint8_t *data, size_t size) {
    // Ensure we have enough data to extract four integers
    if (size < 16) {
        return 0;
    }

    // Extract four integers from the input data
    int ncid = *(const int *)(data);
    int varid = *(const int *)(data + 4);
    int quantize_mode = *(const int *)(data + 8);
    int nsd = *(const int *)(data + 12);

    // Call the function-under-test
    nc_def_var_quantize(ncid, varid, quantize_mode, nsd);

    return 0;
}