#include <stdint.h>
#include <stddef.h>
#include <hdf5.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput_238(const uint8_t *data, size_t size) {
    hid_t file_id, dataset_id, dapl_id;
    char *dataset_name;
    herr_t status;

    // Ensure the input size is sufficient for a string
    if (size < 1) {
        return 0;
    }

    // Create a temporary file to work with
    file_id = H5Fcreate("tempfile.h5", H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
    if (file_id < 0) {
        return 0;
    }

    // Allocate memory for dataset name and ensure it's null-terminated
    dataset_name = (char *)malloc(size + 1);
    if (dataset_name == NULL) {
        H5Fclose(file_id);
        return 0;
    }
    memcpy(dataset_name, data, size);
    dataset_name[size] = '\0';

    // Create a simple dataset to ensure the file has something to open
    hsize_t dims[1] = {10};
    hid_t space_id = H5Screate_simple(1, dims, NULL);
    dataset_id = H5Dcreate2(file_id, "dataset", H5T_NATIVE_INT, space_id, H5P_DEFAULT, H5P_DEFAULT, H5P_DEFAULT);
    H5Sclose(space_id);

    // Open the dataset using the fuzzed dataset name
    dapl_id = H5P_DEFAULT; // Use default dataset access property list
    hid_t opened_dataset_id = H5Dopen2(file_id, dataset_name, dapl_id);

    // Clean up
    if (opened_dataset_id >= 0) {
        H5Dclose(opened_dataset_id);
    }
    H5Dclose(dataset_id);
    H5Fclose(file_id);
    free(dataset_name);

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

    if(size < 2 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_238(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
