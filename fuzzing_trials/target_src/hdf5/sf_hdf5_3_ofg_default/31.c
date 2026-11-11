#include <stdint.h>
#include <stdlib.h>
#include <hdf5.h>
#include <string.h>

int LLVMFuzzerTestOneInput_31(const uint8_t *data, size_t size) {
    // Ensure that the input data is large enough to be used
    if (size < 1) {
        return 0;
    }

    // Create a temporary file to use with HDF5
    hid_t file_id = H5Fcreate("tempfile.h5", H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
    if (file_id < 0) {
        return 0;
    }

    // Use the first byte of data to create a simple string for the group name
    char group_name[256];
    snprintf(group_name, sizeof(group_name), "group_%d", data[0]);

    // Create some default property lists
    hid_t lcpl_id = H5Pcreate(H5P_LINK_CREATE);
    hid_t gcpl_id = H5Pcreate(H5P_GROUP_CREATE);
    hid_t gapl_id = H5Pcreate(H5P_GROUP_ACCESS);

    if (lcpl_id < 0 || gcpl_id < 0 || gapl_id < 0) {
        H5Fclose(file_id);
        return 0;
    }

    // Call the function-under-test
    hid_t group_id = H5Gcreate2(file_id, group_name, lcpl_id, gcpl_id, gapl_id);

    // Clean up resources
    if (group_id >= 0) {
        H5Gclose(group_id);
    }
    H5Pclose(lcpl_id);
    H5Pclose(gcpl_id);
    H5Pclose(gapl_id);
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

    LLVMFuzzerTestOneInput_31(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
