#include <stdint.h>
#include <stddef.h>
#include "netcdf.h"

int LLVMFuzzerTestOneInput_74(const uint8_t *data, size_t size) {
    if (size < 2 * sizeof(nc_type) + sizeof(int)) {
        return 0;
    }

    int ncid1 = 1; // Example non-zero value
    int ncid2 = 2; // Example non-zero value

    nc_type xtype1 = *(nc_type *)(data);
    nc_type xtype2 = *(nc_type *)(data + sizeof(nc_type));

    int equal = 0;

    nc_inq_type_equal(ncid1, xtype1, ncid2, xtype2, &equal);

    return 0;
}