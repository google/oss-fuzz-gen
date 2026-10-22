#include <stdint.h>
#include <stdlib.h>
#include <hdf5.h>

int LLVMFuzzerTestOneInput_30(const uint8_t *data, size_t size) {
    // Ensure there is enough data to extract a filename and other parameters
    if (size < 10) {
        return 0;
    }

    // Initialize HDF5 library
    H5open();

    // Extract a filename from the data
    char filename[6];
    for (int i = 0; i < 5; i++) {
        filename[i] = (char)data[i];
    }
    filename[5] = '\0'; // Null-terminate the string

    // Create a file with the extracted filename
    hid_t file_id = H5Fcreate(filename, H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
    if (file_id < 0) {
        return 0;
    }

    // Extract other parameters from the data
    hid_t space_id = (hid_t)data[5];
    hid_t type_id = (hid_t)data[6];
    hid_t lcpl_id = (hid_t)data[7];
    hid_t dcpl_id = (hid_t)data[8];
    hid_t dapl_id = (hid_t)data[9];

    // Call the function-under-test
    hid_t dataset_id = H5Dcreate2(file_id, filename, type_id, space_id, lcpl_id, dcpl_id, dapl_id);

    // Close the dataset and file
    if (dataset_id >= 0) {
        H5Dclose(dataset_id);
    }
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

    LLVMFuzzerTestOneInput_30(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
