#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <hdf5.h>

int LLVMFuzzerTestOneInput_14(const uint8_t *data, size_t size) {
    // Initialize HDF5 library
    H5open();

    // Create a temporary file to work with
    hid_t file_id = H5Fcreate("tempfile.h5", H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
    if (file_id < 0) {
        return 0; // Unable to create file, exit
    }

    // Ensure the dataset name is null-terminated and not empty
    char dataset_name[256];
    if (size > 0) {
        size_t name_length = size < 255 ? size : 255;
        memcpy(dataset_name, data, name_length);
        dataset_name[name_length] = '\0';
    } else {
        strcpy(dataset_name, "default_dataset");
    }

    // Initialize other parameters with default valid values
    hid_t space_id = H5Screate(H5S_SCALAR); // Create a simple dataspace
    hid_t type_id = H5T_NATIVE_INT; // Use a native integer datatype
    hid_t lcpl_id = H5P_DEFAULT; // Use default link creation property list
    hid_t dcpl_id = H5P_DEFAULT; // Use default dataset creation property list
    hid_t dapl_id = H5P_DEFAULT; // Use default dataset access property list

    // Call the function-under-test
    hid_t dataset_id = H5Dcreate2(file_id, dataset_name, type_id, space_id, lcpl_id, dcpl_id, dapl_id);

    // Clean up
    if (dataset_id >= 0) {
        H5Dclose(dataset_id);
    }
    H5Sclose(space_id);
    H5Fclose(file_id);

    // Terminate HDF5 library
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

    LLVMFuzzerTestOneInput_14(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
