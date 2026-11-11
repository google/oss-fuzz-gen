#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <hdf5.h>

int LLVMFuzzerTestOneInput_12(const uint8_t *data, size_t size) {
    // Declare variables
    hid_t file_id, space_id, type_id, lcpl_id, dcpl_id, dapl_id;
    char dataset_name[20]; // Assuming a reasonable length for dataset name

    // Initialize the HDF5 library
    H5open();

    // Create a new file using default properties.
    file_id = H5Fcreate("fuzz_test.h5", H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);

    // Create a simple dataspace with a single dimension.
    hsize_t dims[1] = {10}; // Example dimension size
    space_id = H5Screate_simple(1, dims, NULL);

    // Use default datatype, link creation, dataset creation, and dataset access properties
    type_id = H5T_NATIVE_INT;
    lcpl_id = H5P_DEFAULT;
    dcpl_id = H5P_DEFAULT;
    dapl_id = H5P_DEFAULT;

    // Ensure the dataset name is null-terminated and not empty
    if (size > 0 && size < sizeof(dataset_name)) {
        memcpy(dataset_name, data, size);
        dataset_name[size] = '\0';
    } else {
        // Default name if size is not suitable
        snprintf(dataset_name, sizeof(dataset_name), "dataset");
    }

    // Call the function-under-test
    hid_t dataset_id = H5Dcreate2(file_id, dataset_name, type_id, space_id, lcpl_id, dcpl_id, dapl_id);

    // Close the dataset and file
    if (dataset_id >= 0) {
        H5Dclose(dataset_id);
    }
    H5Sclose(space_id);
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

    LLVMFuzzerTestOneInput_12(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
