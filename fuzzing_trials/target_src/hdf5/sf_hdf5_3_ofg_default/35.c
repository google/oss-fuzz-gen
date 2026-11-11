#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <hdf5.h>

int LLVMFuzzerTestOneInput_35(const uint8_t *data, size_t size) {
    // Initialize HDF5 library
    H5open();

    // Ensure the data size is sufficient for a valid string
    if (size < 2) {
        H5close();
        return 0;
    }

    // Create a file using the HDF5 library
    hid_t file_id = H5Fcreate("fuzz_test.h5", H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
    if (file_id < 0) {
        H5close();
        return 0; // Failed to create file
    }

    // Use the data as a string for the group name
    char group_name[256];
    size_t group_name_length = size < 255 ? size : 255;
    for (size_t i = 0; i < group_name_length; i++) {
        group_name[i] = (char)data[i];
    }
    group_name[group_name_length] = '\0';

    // Create a group in the file
    hid_t group_id = H5Gcreate2(file_id, group_name, H5P_DEFAULT, H5P_DEFAULT, H5P_DEFAULT);

    // Close the group if it was successfully created
    if (group_id >= 0) {
        H5Gclose(group_id);
    }

    // Create a dataset within the group to ensure more code paths are executed
    if (group_id >= 0) {
        hsize_t dims[1] = {10};
        hid_t dataspace_id = H5Screate_simple(1, dims, NULL);
        if (dataspace_id >= 0) {
            hid_t dataset_id = H5Dcreate2(group_id, "dataset", H5T_NATIVE_INT, dataspace_id, H5P_DEFAULT, H5P_DEFAULT, H5P_DEFAULT);
            if (dataset_id >= 0) {
                H5Dclose(dataset_id);
            }
            H5Sclose(dataspace_id);
        }
    }

    // Close the file
    H5Fclose(file_id);

    // Close the HDF5 library
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

    LLVMFuzzerTestOneInput_35(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
