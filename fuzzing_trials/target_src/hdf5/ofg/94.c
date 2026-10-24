#include <stdint.h>
#include <stddef.h>
#include <hdf5.h>

int LLVMFuzzerTestOneInput_94(const uint8_t *data, size_t size) {
    // Initialize variables for H5Acreate_by_name
    hid_t loc_id = 1;  // Assuming a valid HDF5 location identifier
    const char *obj_name = "test_object";  // Sample object name
    const char *attr_name = "test_attribute";  // Sample attribute name
    hid_t type_id = H5T_NATIVE_INT;  // Sample datatype identifier
    hid_t space_id = H5S_SCALAR;  // Sample dataspace identifier
    hid_t acpl_id = H5P_DEFAULT;  // Attribute creation property list
    hid_t aapl_id = H5P_DEFAULT;  // Attribute access property list
    hid_t lapl_id = H5P_DEFAULT;  // Link access property list

    // Call the function-under-test
    hid_t attr_id = H5Acreate_by_name(loc_id, obj_name, attr_name, type_id, space_id, acpl_id, aapl_id, lapl_id);

    // Close the attribute if it was successfully created
    if (attr_id >= 0) {
        H5Aclose(attr_id);
    }

    return 0;
}
#ifdef INC_MAIN
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
int main(int argc, char *argv[])
{
    FILE *f;
    uint8_t *data = NULL;
    long size;

    if(argc < 2)
        exit(0);

    f = fopen(argv[1], "rb");
    if(f == NULL)
        exit(0);

    fseek(f, 0, SEEK_END);

    size = ftell(f);
    rewind(f);

    if(size < 2 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_94(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
