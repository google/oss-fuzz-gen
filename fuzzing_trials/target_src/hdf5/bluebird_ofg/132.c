#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include "hdf5.h"
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput_132(const uint8_t *data, size_t size) {
    // Ensure size is sufficient for creating a valid string
    if (size < 1) {
        return 0;
    }

    // Create a temporary HDF5 file
    hid_t file_id = H5Fcreate("tempfile.h5", H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
    if (file_id < 0) {
        return 0;
    }

    // Create a dataset in the file to attach an attribute
    hid_t dataspace_id = H5Screate(H5S_SCALAR);
    hid_t dataset_id = H5Dcreate2(file_id, "dataset", H5T_NATIVE_INT, dataspace_id, H5P_DEFAULT, H5P_DEFAULT, H5P_DEFAULT);
    H5Sclose(dataspace_id);

    if (dataset_id < 0) {
        H5Fclose(file_id);
        return 0;
    }

    // Create an attribute for the dataset
    hid_t attr_id = H5Acreate2(dataset_id, "attribute", H5T_NATIVE_INT, H5S_SCALAR, H5P_DEFAULT, H5P_DEFAULT);
    H5Aclose(attr_id);

    // Use the fuzz data as the attribute name
    char *attr_name = (char *)malloc(size + 1);
    memcpy(attr_name, data, size);
    attr_name[size] = '\0'; // Null-terminate the string

    // Call the function-under-test
    hid_t result = H5Aopen(dataset_id, attr_name, H5P_DEFAULT);

    // Clean up
    free(attr_name);
    H5Dclose(dataset_id);
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

    LLVMFuzzerTestOneInput_132(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
