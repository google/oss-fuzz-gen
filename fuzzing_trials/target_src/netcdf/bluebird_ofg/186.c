#include <stdint.h>
#include <stddef.h>

// Function-under-test declaration
int nc_inq_var_quantize(int ncid, int varid, int *quantize_modep, int *nsd_p);

int LLVMFuzzerTestOneInput_186(const uint8_t *data, size_t size) {
    if (size < sizeof(int) * 4) {
        return 0;
    }

    // Extract integers from the data
    int ncid = *(const int *)(data);
    int varid = *(const int *)(data + sizeof(int));
    int quantize_mode = *(const int *)(data + 2 * sizeof(int));
    int nsd = *(const int *)(data + 3 * sizeof(int));

    // Call the function-under-test
    nc_inq_var_quantize(ncid, varid, &quantize_mode, &nsd);

    return 0;
}