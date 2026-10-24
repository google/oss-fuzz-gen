#include <stdint.h>
#include <stdlib.h>
#include <hdf5.h>
#include <string.h>

int LLVMFuzzerTestOneInput_24(const uint8_t *data, size_t size) {
    // Ensure there's enough data to create a valid string and identifiers
    if (size < 10) {
        return 0;
    }

    // Initialize HDF5 library
    H5open();

    // Create a temporary file to work with
    hid_t file_id = H5Fcreate("tempfile.h5", H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);

    // Use parts of the data to create identifiers
    hid_t space_id = H5Screate(H5S_SIMPLE);
    hid_t type_id = H5Tcopy(H5T_NATIVE_INT);
    hid_t lcpl_id = H5Pcreate(H5P_LINK_CREATE);
    hid_t dcpl_id = H5Pcreate(H5P_DATASET_CREATE);
    hid_t dapl_id = H5Pcreate(H5P_DATASET_ACCESS);

    // Use a portion of the data as a dataset name
    size_t name_len = size > 50 ? 50 : size;  // Limit the length of the name
    char dataset_name[51];
    strncpy(dataset_name, (const char *)data, name_len);
    dataset_name[name_len] = '\0';  // Null-terminate the string

    // Call the function-under-test
    hid_t dataset_id = H5Dcreate2(file_id, dataset_name, type_id, space_id, lcpl_id, dcpl_id, dapl_id);

    // Clean up
    if (dataset_id >= 0) {
        H5Dclose(dataset_id);
    }
    H5Sclose(space_id);
    H5Tclose(type_id);
    H5Pclose(lcpl_id);
    H5Pclose(dcpl_id);
    H5Pclose(dapl_id);
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

    LLVMFuzzerTestOneInput_24(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
