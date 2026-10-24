#include <stdint.h>
#include <stdlib.h>
#include <hdf5.h>
#include <string.h>

int LLVMFuzzerTestOneInput_33(const uint8_t *data, size_t size) {
    hid_t file_id, space_id, dcpl_id, dapl_id, lcpl_id, type_id, dataset_id;
    char dataset_name[256];

    // Ensure data is large enough to create a valid string for the dataset name
    if (size < 1) {
        return 0;
    }

    // Initialize HDF5 library
    H5open();

    // Create a new file using default properties.
    file_id = H5Fcreate("fuzz_test.h5", H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);

    // Create a simple dataspace with one dimension.
    hsize_t dims[1] = {10};
    space_id = H5Screate_simple(1, dims, NULL);

    // Use first byte of data to create a dataset name
    size_t name_length = (size < 255) ? size : 255;
    memcpy(dataset_name, data, name_length);
    dataset_name[name_length] = '\0';

    // Use default property lists
    dcpl_id = H5P_DEFAULT;
    dapl_id = H5P_DEFAULT;
    lcpl_id = H5P_DEFAULT;
    type_id = H5T_NATIVE_INT;

    // Call the function-under-test
    dataset_id = H5Dcreate2(file_id, dataset_name, type_id, space_id, lcpl_id, dcpl_id, dapl_id);

    // Close resources
    if (dataset_id >= 0) {
        H5Dclose(dataset_id);
    }
    H5Sclose(space_id);
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

    LLVMFuzzerTestOneInput_33(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
