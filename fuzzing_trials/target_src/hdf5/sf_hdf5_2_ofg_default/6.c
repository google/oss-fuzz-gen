#include <stdint.h>
#include <stddef.h>
#include <hdf5.h>

int LLVMFuzzerTestOneInput_6(const uint8_t *data, size_t size) {
    // Ensure there is enough data to create a valid string
    if (size < 1) return 0;

    // Create a null-terminated string from the input data
    char name[256];
    size_t name_len = (size < 255) ? size : 255;
    for (size_t i = 0; i < name_len; i++) {
        name[i] = data[i];
    }
    name[name_len] = '\0';

    // Initialize HDF5 library
    H5open();

    // Create file and dataspace identifiers
    hid_t file_id = H5Fcreate("fuzz_test.h5", H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
    hid_t space_id = H5Screate(H5S_SCALAR);

    // Use default property lists
    hid_t dcpl_id = H5P_DEFAULT;
    hid_t dapl_id = H5P_DEFAULT;
    hid_t lcpl_id = H5P_DEFAULT;

    // Call the function-under-test
    hid_t dataset_id = H5Dcreate2(file_id, name, H5T_NATIVE_INT, space_id, lcpl_id, dcpl_id, dapl_id);

    // Close the dataset, dataspace, and file
    if (dataset_id >= 0) {
        H5Dclose(dataset_id);
    }
    H5Sclose(space_id);
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

    LLVMFuzzerTestOneInput_6(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
