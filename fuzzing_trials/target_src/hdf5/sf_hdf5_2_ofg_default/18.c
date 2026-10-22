#include <stdint.h>
#include <stdlib.h>
#include <hdf5.h>
#include <string.h>

int LLVMFuzzerTestOneInput_18(const uint8_t *data, size_t size) {
    // Declare and initialize all variables
    hid_t file_id = -1;
    hid_t dataset_id = -1;
    hid_t dataspace_id = -1;
    hid_t type_id = -1;
    hid_t lcpl_id = H5P_DEFAULT;
    hid_t dcpl_id = H5P_DEFAULT;
    hid_t dapl_id = H5P_DEFAULT;
    char dataset_name[256];

    // Ensure the dataset name is null-terminated and not empty
    if (size < 1 || size >= sizeof(dataset_name)) {
        return 0;
    }
    memcpy(dataset_name, data, size);
    dataset_name[size] = '\0';

    // Create a simple dataspace
    hsize_t dims[1] = {10};
    dataspace_id = H5Screate_simple(1, dims, NULL);
    if (dataspace_id < 0) {
        goto cleanup;
    }

    // Create a file to work with
    file_id = H5Fcreate("testfile.h5", H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
    if (file_id < 0) {
        goto cleanup;
    }

    // Use H5T_NATIVE_INT as a simple type
    type_id = H5Tcopy(H5T_NATIVE_INT);
    if (type_id < 0) {
        goto cleanup;
    }

    // Call the function under test
    dataset_id = H5Dcreate2(file_id, dataset_name, type_id, dataspace_id, lcpl_id, dcpl_id, dapl_id);

cleanup:
    // Close any open identifiers
    if (dataset_id >= 0) H5Dclose(dataset_id);
    if (dataspace_id >= 0) H5Sclose(dataspace_id);
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

    LLVMFuzzerTestOneInput_18(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
