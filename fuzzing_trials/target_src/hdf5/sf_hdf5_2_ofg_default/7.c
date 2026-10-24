#include <stdint.h>
#include <stdlib.h>
#include <hdf5.h>
#include <string.h>

int LLVMFuzzerTestOneInput_7(const uint8_t *data, size_t size) {
    // Initialize HDF5 library
    H5open();

    // Create a temporary file to use as the HDF5 file
    const char *filename = "fuzz_test_file.h5";
    hid_t file_id = H5Fcreate(filename, H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
    if (file_id < 0) {
        return 0; // Unable to create file, exit early
    }

    // Ensure the dataset name is null-terminated and non-empty
    char dataset_name[256];
    size_t name_len = size < 255 ? size : 255;
    if (name_len > 0) {
        memcpy(dataset_name, data, name_len);
        dataset_name[name_len] = '\0';
    } else {
        // If size is 0, provide a default name
        strcpy(dataset_name, "default_dataset_name");
    }

    // Create dataspace and datatype
    hsize_t dims[1] = {10}; // Example dimension
    hid_t space_id = H5Screate_simple(1, dims, NULL);
    hid_t type_id = H5Tcopy(H5T_NATIVE_INT);

    // Use default properties for creation
    hid_t lcpl_id = H5P_DEFAULT;
    hid_t dcpl_id = H5P_DEFAULT;
    hid_t dapl_id = H5P_DEFAULT;

    // Call the function-under-test
    hid_t dataset_id = H5Dcreate2(file_id, dataset_name, type_id, space_id, lcpl_id, dcpl_id, dapl_id);

    // Clean up resources
    if (dataset_id >= 0) {
        H5Dclose(dataset_id);
    }
    H5Sclose(space_id);
    H5Tclose(type_id);
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

    LLVMFuzzerTestOneInput_7(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
