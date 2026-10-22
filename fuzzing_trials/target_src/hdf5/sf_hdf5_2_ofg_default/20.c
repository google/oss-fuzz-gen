#include <stdint.h>
#include <stdlib.h>
#include <hdf5.h>
#include <string.h>

int LLVMFuzzerTestOneInput_20(const uint8_t *data, size_t size) {
    // Declare and initialize variables
    hid_t file_id = H5I_INVALID_HID;
    hid_t space_id = H5I_INVALID_HID;
    hid_t type_id = H5I_INVALID_HID;
    hid_t lcpl_id = H5P_DEFAULT;
    hid_t dcpl_id = H5P_DEFAULT;
    hid_t dapl_id = H5P_DEFAULT;
    hid_t dataset_id = H5I_INVALID_HID;

    // Create a temporary file to use with HDF5
    file_id = H5Fcreate("tempfile.h5", H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
    if (file_id < 0) goto cleanup;

    // Create a dataspace
    hsize_t dims[1] = {10};
    space_id = H5Screate_simple(1, dims, NULL);
    if (space_id < 0) goto cleanup;

    // Create a datatype
    type_id = H5Tcopy(H5T_NATIVE_INT);
    if (type_id < 0) goto cleanup;

    // Ensure the dataset name is null-terminated and not empty
    char dataset_name[256];
    if (size > 0 && size < sizeof(dataset_name)) {
        memcpy(dataset_name, data, size);
        dataset_name[size] = '\0';
    } else {
        strcpy(dataset_name, "default_dataset");
    }

    // Call the function-under-test
    dataset_id = H5Dcreate2(file_id, dataset_name, type_id, space_id, lcpl_id, dcpl_id, dapl_id);

cleanup:
    // Clean up resources
    if (dataset_id >= 0) H5Dclose(dataset_id);
    if (space_id >= 0) H5Sclose(space_id);
    if (type_id >= 0) H5Tclose(type_id);
    if (file_id >= 0) H5Fclose(file_id);

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

    LLVMFuzzerTestOneInput_20(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
