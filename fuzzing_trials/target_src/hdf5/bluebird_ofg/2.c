#include <sys/stat.h>
#include <string.h>
#include <stdint.h>
#include "hdf5.h"

int LLVMFuzzerTestOneInput_2(const uint8_t *data, size_t size) {
    // Initialize variables for the function parameters
    hid_t file_id, dataspace_id, datatype_id, dcpl_id, dapl_id;
    hid_t dataset_id;

    // Create a temporary HDF5 file to use for testing
    file_id = H5Fcreate("tempfile.h5", H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
    if (file_id < 0) {
        return 0; // Failed to create file
    }

    // Create a simple dataspace
    hsize_t dims[2] = {10, 10};
    dataspace_id = H5Screate_simple(2, dims, NULL);
    if (dataspace_id < 0) {
        H5Fclose(file_id);
        return 0; // Failed to create dataspace
    }

    // Create a datatype
    datatype_id = H5Tcopy(H5T_NATIVE_INT);
    if (datatype_id < 0) {
        H5Sclose(dataspace_id);
        H5Fclose(file_id);
        return 0; // Failed to create datatype
    }

    // Use default property lists
    dcpl_id = H5P_DEFAULT;
    dapl_id = H5P_DEFAULT;

    // Call the function-under-test
    dataset_id = H5Dcreate_anon(file_id, datatype_id, dataspace_id, dcpl_id, dapl_id);

    // Write the fuzzing input data to the dataset if it was created successfully
    if (dataset_id >= 0 && size > 0) {
        hsize_t start[2] = {0, 0};
        hsize_t count[2] = {1, size < 10 ? size : 10};
        H5Sselect_hyperslab(dataspace_id, H5S_SELECT_SET, start, NULL, count, NULL);
        H5Dwrite(dataset_id, H5T_NATIVE_UINT8, H5S_ALL, dataspace_id, H5P_DEFAULT, data);
        H5Dclose(dataset_id);
    }

    // Cleanup
    H5Tclose(datatype_id);
    H5Sclose(dataspace_id);
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

    LLVMFuzzerTestOneInput_2(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
