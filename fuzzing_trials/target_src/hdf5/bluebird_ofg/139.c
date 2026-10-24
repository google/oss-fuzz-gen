#include <sys/stat.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include "hdf5.h"

int LLVMFuzzerTestOneInput_139(const uint8_t *data, size_t size) {
    // Initialize HDF5 library
    H5open();

    // Create a memory file
    hid_t file_id = H5Fcreate("fuzzfile.h5", H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
    if (file_id < 0) {
        return 0;
    }

    // Create a dataspace
    hsize_t dims[1] = {size > 0 ? size : 1}; // Ensure at least one element
    hid_t dataspace_id = H5Screate_simple(1, dims, NULL);
    if (dataspace_id < 0) {
        H5Fclose(file_id);
        return 0;
    }

    // Create a dataset
    hid_t dataset_id = H5Dcreate2(file_id, "dataset", H5T_NATIVE_UINT8, dataspace_id, H5P_DEFAULT, H5P_DEFAULT, H5P_DEFAULT);
    if (dataset_id < 0) {
        H5Sclose(dataspace_id);
        H5Fclose(file_id);
        return 0;
    }

    // Create a datatype
    hid_t datatype_id = H5Tcopy(H5T_NATIVE_UINT8);
    if (datatype_id < 0) {
        H5Dclose(dataset_id);
        H5Sclose(dataspace_id);
        H5Fclose(file_id);
        return 0;
    }

    // Create a dataspace for memory
    hid_t memspace_id = H5Screate_simple(1, dims, NULL);
    if (memspace_id < 0) {
        H5Tclose(datatype_id);
        H5Dclose(dataset_id);
        H5Sclose(dataspace_id);
        H5Fclose(file_id);
        return 0;
    }

    // Write data to the dataset
    herr_t status = H5Dwrite(dataset_id, datatype_id, memspace_id, dataspace_id, H5P_DEFAULT, data);

    // Clean up
    H5Sclose(memspace_id);
    H5Tclose(datatype_id);
    H5Dclose(dataset_id);
    H5Sclose(dataspace_id);
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

    LLVMFuzzerTestOneInput_139(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
