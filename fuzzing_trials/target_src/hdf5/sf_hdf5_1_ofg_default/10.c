#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <hdf5.h>
#include <string.h>

int LLVMFuzzerTestOneInput_10(const uint8_t *data, size_t size) {
    // Initialize HDF5 library
    H5open();

    // Create a temporary file to use as a HDF5 file
    char filename[] = "tempfileXXXXXX";
    int fd = mkstemp(filename);
    if (fd < 0) {
        return 0;
    }
    close(fd);

    // Create a new HDF5 file
    hid_t file_id = H5Fcreate(filename, H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
    if (file_id < 0) {
        remove(filename);
        return 0;
    }

    // Create a group in the file
    hid_t group_id = H5Gcreate2(file_id, "/fuzz_group", H5P_DEFAULT, H5P_DEFAULT, H5P_DEFAULT);
    if (group_id < 0) {
        H5Fclose(file_id);
        remove(filename);
        return 0;
    }

    // Create a dataset within the group using the fuzzing input
    hsize_t dims[1] = {size};
    hid_t space_id = H5Screate_simple(1, dims, NULL);
    if (space_id < 0) {
        H5Gclose(group_id);
        H5Fclose(file_id);
        remove(filename);
        return 0;
    }

    hid_t dset_id = H5Dcreate2(group_id, "fuzz_dataset", H5T_NATIVE_UINT8, space_id, H5P_DEFAULT, H5P_DEFAULT, H5P_DEFAULT);
    if (dset_id < 0) {
        H5Sclose(space_id);
        H5Gclose(group_id);
        H5Fclose(file_id);
        remove(filename);
        return 0;
    }

    // Write the fuzzing input data to the dataset
    herr_t status = H5Dwrite(dset_id, H5T_NATIVE_UINT8, H5S_ALL, H5S_ALL, H5P_DEFAULT, data);
    if (status < 0) {
        H5Dclose(dset_id);
        H5Sclose(space_id);
        H5Gclose(group_id);
        H5Fclose(file_id);
        remove(filename);
        return 0;
    }

    // Prepare the H5G_info_t structure
    H5G_info_t group_info;

    // Call the function-under-test
    status = H5Gget_info(group_id, &group_info);

    // Clean up
    H5Dclose(dset_id);
    H5Sclose(space_id);
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

    LLVMFuzzerTestOneInput_10(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
