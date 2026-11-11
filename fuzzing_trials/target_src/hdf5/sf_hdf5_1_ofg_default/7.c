#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>  // Include for close() and mkstemp()
#include <hdf5.h>

int LLVMFuzzerTestOneInput_7(const uint8_t *data, size_t size) {
    // Initialize HDF5 library
    H5open();

    // Create a temporary file to use as a HDF5 file
    char filename[] = "tempfileXXXXXX.h5";
    int fd = mkstemp(filename);
    if (fd < 0) {
        return 0;
    }
    close(fd);

    // Create a new HDF5 file
    hid_t file_id = H5Fcreate(filename, H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
    if (file_id < 0) {
        return 0;
    }

    // Create a group in the file
    hid_t group_id = H5Gcreate2(file_id, "/test_group", H5P_DEFAULT, H5P_DEFAULT, H5P_DEFAULT);
    if (group_id < 0) {
        H5Fclose(file_id);
        return 0;
    }

    // Prepare the group_info structure
    H5G_info_t group_info;

    // Modify the fuzzing input to affect the function under test
    // Instead of calling H5Gget_info directly, we can create a dataset using the input data
    if (size > 0) {
        // Create a dataspace for the dataset
        hsize_t dims[1] = {size};
        hid_t dataspace_id = H5Screate_simple(1, dims, NULL);
        if (dataspace_id < 0) {
            H5Gclose(group_id);
            H5Fclose(file_id);
            remove(filename);
            H5close();
            return 0;
        }

        // Create a dataset
        hid_t dataset_id = H5Dcreate2(group_id, "test_dataset", H5T_NATIVE_UINT8, dataspace_id, H5P_DEFAULT, H5P_DEFAULT, H5P_DEFAULT);
        if (dataset_id < 0) {
            H5Sclose(dataspace_id);
            H5Gclose(group_id);
            H5Fclose(file_id);
            remove(filename);
            H5close();
            return 0;
        }

        // Write the input data to the dataset
        herr_t write_status = H5Dwrite(dataset_id, H5T_NATIVE_UINT8, H5S_ALL, H5S_ALL, H5P_DEFAULT, data);
        if (write_status < 0) {
            H5Dclose(dataset_id);
            H5Sclose(dataspace_id);
            H5Gclose(group_id);
            H5Fclose(file_id);
            remove(filename);
            H5close();
            return 0;
        }

        // Clean up dataset and dataspace
        H5Dclose(dataset_id);
        H5Sclose(dataspace_id);
    }

    // Call the function-under-test
    herr_t status = H5Gget_info(group_id, &group_info);

    // Clean up
    H5Gclose(group_id);
    H5Fclose(file_id);
    remove(filename);

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

    LLVMFuzzerTestOneInput_7(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
