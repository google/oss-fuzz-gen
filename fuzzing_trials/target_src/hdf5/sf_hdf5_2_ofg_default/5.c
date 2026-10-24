#include <stdint.h>
#include <stdlib.h>
#include <hdf5.h>
#include <string.h>

int LLVMFuzzerTestOneInput_5(const uint8_t *data, size_t size) {
    // Initialize variables for H5Dcreate2 parameters
    hid_t file_id = -1;
    hid_t space_id = -1;
    hid_t type_id = -1;
    hid_t dcpl_id = -1;
    hid_t dapl_id = -1;
    hid_t lcpl_id = -1;
    char dataset_name[256] = "default_dataset";

    // Ensure the data size is sufficient for testing
    if (size < 1) {
        return 0;
    }

    // Create a temporary file to use with HDF5
    file_id = H5Fcreate("tempfile.h5", H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
    if (file_id < 0) {
        return 0;
    }

    // Create a simple dataspace
    hsize_t dims[1] = {10};
    space_id = H5Screate_simple(1, dims, NULL);
    if (space_id < 0) {
        H5Fclose(file_id);
        return 0;
    }

    // Use a fixed datatype for simplicity
    type_id = H5Tcopy(H5T_NATIVE_INT);
    if (type_id < 0) {
        H5Sclose(space_id);
        H5Fclose(file_id);
        return 0;
    }

    // Copy some data into the dataset name
    size_t name_length = size < 255 ? size : 255;
    memcpy(dataset_name, data, name_length);
    dataset_name[name_length] = '\0';

    // Call the function-under-test
    hid_t dataset_id = H5Dcreate2(file_id, dataset_name, type_id, space_id, lcpl_id, dcpl_id, dapl_id);

    // Clean up
    if (dataset_id >= 0) {
        H5Dclose(dataset_id);
    }
    H5Tclose(type_id);
    H5Sclose(space_id);
    H5Fclose(file_id);

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

    LLVMFuzzerTestOneInput_5(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
