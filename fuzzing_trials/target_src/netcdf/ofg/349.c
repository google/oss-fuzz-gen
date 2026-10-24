#include <stddef.h>
#include <stdint.h>
#include <netcdf.h>

int LLVMFuzzerTestOneInput_349(const uint8_t *data, size_t size) {
    // Ensure the input data is large enough to fill all parameters
    if (size < sizeof(int) + sizeof(nc_type) + sizeof(size_t) + sizeof(nc_type) + sizeof(size_t) + sizeof(int)) {
        return 0;
    }

    // Initialize parameters
    int ncid = *(int *)data;
    data += sizeof(int);

    nc_type xtype = *(nc_type *)data;
    data += sizeof(nc_type);

    char name[256];
    size_t namelen = sizeof(name) - 1;

    size_t *sizep = (size_t *)data;
    data += sizeof(size_t);

    nc_type *base_nc_typep = (nc_type *)data;
    data += sizeof(nc_type);

    size_t *nfieldsp = (size_t *)data;
    data += sizeof(size_t);

    int *classp = (int *)data;

    // Call the function-under-test
    nc_inq_user_type(ncid, xtype, name, sizep, base_nc_typep, nfieldsp, classp);

    return 0;
}