#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <hdf5.h>

int LLVMFuzzerTestOneInput_34(const uint8_t *data, size_t size) {
    hid_t loc_id;
    H5G_info_t group_info;
    herr_t status;

    // Initialize HDF5 library
    H5open();

    // Create a temporary file to simulate an HDF5 file
    hid_t file_id = H5Fcreate("tempfile.h5", H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
    if (file_id < 0) {
        return 0; // Failed to create file, exit early
    }

    // Use the input data to create a group name
    char group_name[256];
    if (size > 0) {
        size_t copy_size = size < 255 ? size : 255;
        memcpy(group_name, data, copy_size);
        group_name[copy_size] = '\0'; // Ensure null-termination
    } else {
        strcpy(group_name, "/default_group");
    }

    // Create a group in the file using the fuzzing input as the group name
    loc_id = H5Gcreate2(file_id, group_name, H5P_DEFAULT, H5P_DEFAULT, H5P_DEFAULT);
    if (loc_id < 0) {
        H5Fclose(file_id);
        return 0; // Failed to create group, exit early
    }

    // Call the function-under-test
    status = H5Gget_info(loc_id, &group_info);

    // Clean up resources
    H5Gclose(loc_id);
    H5Fclose(file_id);

    // Close HDF5 library
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

    if(size < 1 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_34(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
