#include <stdint.h>
#include <stddef.h>
#include <hdf5.h>
#include <stdio.h>

int LLVMFuzzerTestOneInput_2(const uint8_t *data, size_t size) {
    // Ensure that the input size is sufficient for our needs
    if (size < 1) {
        return 0;
    }

    // Initialize HDF5 library
    H5open();

    // Create a temporary file to use as an HDF5 file
    hid_t file_id = H5Fcreate("tempfile.h5", H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
    if (file_id < 0) {
        return 0;
    }

    // Use the first byte of data to create a simple dataset name
    char dataset_name[10];
    snprintf(dataset_name, sizeof(dataset_name), "ds_%u", data[0]);

    // Create a dataspace
    hsize_t dims[1] = {10}; // Example dimension
    hid_t dataspace_id = H5Screate_simple(1, dims, NULL);
    if (dataspace_id < 0) {
        H5Fclose(file_id);
        return 0;
    }

    // Use the remaining bytes of data to create property lists and datatype
    hid_t dcpl_id = H5Pcreate(H5P_DATASET_CREATE);
    hid_t dapl_id = H5Pcreate(H5P_DATASET_ACCESS);
    hid_t dtype_id = H5Tcopy(H5T_NATIVE_INT);

    // Call the function under test
    hid_t dataset_id = H5Dcreate2(file_id, dataset_name, dtype_id, dataspace_id, H5P_DEFAULT, dcpl_id, dapl_id);

    // Clean up
    if (dataset_id >= 0) {
        H5Dclose(dataset_id);
    }
    H5Tclose(dtype_id);
    H5Pclose(dcpl_id);
    H5Pclose(dapl_id);
    H5Sclose(dataspace_id);
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

    LLVMFuzzerTestOneInput_2(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
