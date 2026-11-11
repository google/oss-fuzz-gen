#include <stdint.h>
#include <stdlib.h>
#include <hdf5.h>

int LLVMFuzzerTestOneInput_114(const uint8_t *data, size_t size) {
    // Initialize HDF5 library
    H5open();

    // Create a temporary file to use as the HDF5 file
    hid_t file_id = H5Fcreate("tempfile.h5", H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
    if (file_id < 0) return 0;

    // Create a group in the file
    hid_t group_id = H5Gcreate2(file_id, "/test_group", H5P_DEFAULT, H5P_DEFAULT, H5P_DEFAULT);
    if (group_id < 0) {
        H5Fclose(file_id);
        return 0;
    }

    // Create a dummy attribute to ensure the function has something to work with
    hid_t dataspace_id = H5Screate(H5S_SCALAR);
    hid_t attr_id = H5Acreate2(group_id, "test_attr", H5T_NATIVE_INT, dataspace_id, H5P_DEFAULT, H5P_DEFAULT);
    if (attr_id < 0) {
        H5Sclose(dataspace_id);
        H5Gclose(group_id);
        H5Fclose(file_id);
        return 0;
    }

    // Close the attribute and dataspace
    H5Aclose(attr_id);
    H5Sclose(dataspace_id);

    // Prepare the parameters for H5Aget_info_by_name
    const char *group_name = "/test_group";
    const char *attr_name = "test_attr";
    H5A_info_t ainfo;
    hid_t lapl_id = H5P_DEFAULT;

    // Call the function-under-test
    herr_t status = H5Aget_info_by_name(group_id, group_name, attr_name, &ainfo, lapl_id);

    // Clean up
    H5Gclose(group_id);
    H5Fclose(file_id);
    H5close();

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

    LLVMFuzzerTestOneInput_114(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
