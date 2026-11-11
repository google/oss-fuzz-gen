#include <sys/stat.h>
#include <string.h>
#include <stdint.h>
#include "hdf5.h"
#include <stdlib.h>

int LLVMFuzzerTestOneInput_69(const uint8_t *data, size_t size) {
    hid_t file_id, dataset_id, dataspace_id;
    herr_t status;
    hsize_t dims[1];

    // Create a new HDF5 file using default properties.
    file_id = H5Fcreate("fuzz_test.h5", H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
    if (file_id < 0) {
        return 0; // Failed to create file, exit early
    }

    // Use the input data to create a dataset
    if (size > 0) {
        dims[0] = size;
        dataspace_id = H5Screate_simple(1, dims, NULL);
        if (dataspace_id >= 0) {
            dataset_id = H5Dcreate2(file_id, "dataset", H5T_NATIVE_UINT8, dataspace_id, 
                                    H5P_DEFAULT, H5P_DEFAULT, H5P_DEFAULT);
            if (dataset_id >= 0) {
                // Write the input data to the dataset
                H5Dwrite(dataset_id, H5T_NATIVE_UINT8, H5S_ALL, H5S_ALL, H5P_DEFAULT, data);
                // Close the dataset
                H5Dclose(dataset_id);
            }
            // Close the dataspace
            H5Sclose(dataspace_id);
        }
    }

    // Call the function-under-test with the created file identifier
    status = H5Fstop_mdc_logging(file_id);

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

    if(size < 1 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_69(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
