#include <sys/stat.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include "hdf5.h"

int LLVMFuzzerTestOneInput_23(const uint8_t *data, size_t size) {
    // Declare and initialize variables
    hid_t dataset_id;
    hsize_t *dims = NULL;
    
    // Ensure size is sufficient for at least one dimension
    if (size < sizeof(hsize_t)) {
        return 0;
    }

    // Create a copy of the input data to use as dimensions
    size_t num_dims = size / sizeof(hsize_t);
    dims = (hsize_t *)malloc(num_dims * sizeof(hsize_t));
    if (dims == NULL) {
        return 0;
    }

    // Copy data into dims
    for (size_t i = 0; i < num_dims; i++) {
        dims[i] = ((const hsize_t *)data)[i];
    }

    // Initialize HDF5 library
    H5open();

    // Create a new HDF5 file and dataset for testing
    hid_t file_id = H5Fcreate("tempfile.h5", H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
    if (file_id < 0) {
        free(dims);
        return 0;
    }

    // Create a dataspace with the initial dimensions
    hid_t dataspace_id = H5Screate_simple(num_dims, dims, NULL);
    if (dataspace_id < 0) {
        H5Fclose(file_id);
        free(dims);
        return 0;
    }

    // Create a dataset
    dataset_id = H5Dcreate2(file_id, "dataset", H5T_NATIVE_INT, dataspace_id, H5P_DEFAULT, H5P_DEFAULT, H5P_DEFAULT);
    if (dataset_id < 0) {
        H5Sclose(dataspace_id);
        H5Fclose(file_id);
        free(dims);
        return 0;
    }

    // Call the function-under-test
    H5Dset_extent(dataset_id, dims);

    // Clean up
    H5Dclose(dataset_id);
    H5Sclose(dataspace_id);
    H5Fclose(file_id);
    free(dims);
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

    LLVMFuzzerTestOneInput_23(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
