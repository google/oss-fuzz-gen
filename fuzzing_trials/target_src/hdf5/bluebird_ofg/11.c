#include <sys/stat.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include "hdf5.h"

int LLVMFuzzerTestOneInput_11(const uint8_t *data, size_t size) {
    // Initialize variables
    hid_t loc_id = H5I_INVALID_HID;  // Invalid ID for initialization
    const char *obj_name = "test_object";
    const char *attr_name = "test_attribute";
    H5A_info_t ainfo;
    hid_t lapl_id = H5P_DEFAULT;  // Default link access property list

    // Create a temporary HDF5 file for testing
    hid_t file_id = H5Fcreate("tempfile.h5", H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
    if (file_id < 0) {
        return 0;  // Return if file creation fails
    }

    // Create a group in the file
    loc_id = H5Gcreate(file_id, obj_name, H5P_DEFAULT, H5P_DEFAULT, H5P_DEFAULT);
    if (loc_id < 0) {
        H5Fclose(file_id);
        return 0;  // Return if group creation fails
    }

    // Create an attribute in the group
    hid_t space_id = H5Screate(H5S_SCALAR);
    hid_t attr_id = H5Acreate(loc_id, attr_name, H5T_NATIVE_INT, space_id, H5P_DEFAULT, H5P_DEFAULT);
    if (attr_id < 0) {
        H5Gclose(loc_id);
        H5Fclose(file_id);
        return 0;  // Return if attribute creation fails
    }

    // Write some data to the attribute
    if (size >= sizeof(int)) {
        H5Awrite(attr_id, H5T_NATIVE_INT, data);
    }

    // Close the attribute and dataspace
    H5Aclose(attr_id);
    H5Sclose(space_id);

    // Call the function-under-test
    herr_t status = H5Aget_info_by_name(loc_id, obj_name, attr_name, &ainfo, lapl_id);

    // Clean up
    H5Gclose(loc_id);
    H5Fclose(file_id);

    // Remove the temporary file
    remove("tempfile.h5");

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

    if(size < 1 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_11(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
