#include <stdint.h>
#include <hdf5.h>

int LLVMFuzzerTestOneInput_8(const uint8_t *data, size_t size) {
    // Declare and initialize variables
    hid_t file_id, dataset_id, dataspace_id;
    _Bool is_enabled = 0;
    _Bool is_active = 0;
    herr_t status;

    // Create a new file using default properties.
    file_id = H5Fcreate("fuzz_test_file.h5", H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
    if (file_id < 0) {
        return 0; // Unable to create file, exit early
    }

    // Define a simple dataspace with a single dimension
    hsize_t dims[1] = {size};
    dataspace_id = H5Screate_simple(1, dims, NULL);
    if (dataspace_id < 0) {
        H5Fclose(file_id);
        return 0; // Unable to create dataspace, exit early
    }

    // Create a dataset within the file
    dataset_id = H5Dcreate2(file_id, "fuzz_dataset", H5T_NATIVE_UINT8, dataspace_id, H5P_DEFAULT, H5P_DEFAULT, H5P_DEFAULT);
    if (dataset_id < 0) {
        H5Sclose(dataspace_id);
        H5Fclose(file_id);
        return 0; // Unable to create dataset, exit early
    }

    // Write the input data to the dataset
    status = H5Dwrite(dataset_id, H5T_NATIVE_UINT8, H5S_ALL, H5S_ALL, H5P_DEFAULT, data);
    if (status < 0) {
        H5Dclose(dataset_id);
        H5Sclose(dataspace_id);
        H5Fclose(file_id);
        return 0; // Unable to write data, exit early
    }

    // Call the function-under-test
    status = H5Fget_mdc_logging_status(file_id, &is_enabled, &is_active);

    // Close the dataset and dataspace
    H5Dclose(dataset_id);
    H5Sclose(dataspace_id);

    // Close the file
    H5Fclose(file_id);

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

    LLVMFuzzerTestOneInput_8(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
