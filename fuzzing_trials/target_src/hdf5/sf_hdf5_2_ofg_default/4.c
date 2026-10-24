#include <stdint.h>
#include <stdlib.h>
#include <hdf5.h>

int LLVMFuzzerTestOneInput_4(const uint8_t *data, size_t size) {
    // Ensure the data size is sufficient for our needs
    if (size < 7) return 0;

    // Initialize the HDF5 library
    H5open();

    // Create a temporary file to store the HDF5 dataset
    hid_t file_id = H5Fcreate("tempfile.h5", H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
    if (file_id < 0) return 0;

    // Extract parameters from the fuzzing input
    hid_t loc_id = (hid_t)data[0];
    const char *name = "dataset";
    hid_t type_id = (hid_t)data[1];
    hid_t space_id = (hid_t)data[2];
    hid_t lcpl_id = (hid_t)data[3];
    hid_t dcpl_id = (hid_t)data[4];
    hid_t dapl_id = (hid_t)data[5];

    // Call the function-under-test
    hid_t dataset_id = H5Dcreate2(file_id, name, type_id, space_id, lcpl_id, dcpl_id, dapl_id);

    // Close the dataset and file if they were successfully created
    if (dataset_id >= 0) {
        H5Dclose(dataset_id);
    }
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

    LLVMFuzzerTestOneInput_4(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
