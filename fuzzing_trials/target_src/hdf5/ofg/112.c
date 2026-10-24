#include <stdint.h>
#include <stdlib.h>
#include <hdf5.h>
#include <string.h>

int LLVMFuzzerTestOneInput_112(const uint8_t *data, size_t size) {
    // Ensure that the size is sufficient to create a valid string
    if (size < 1) {
        return 0;
    }

    // Create a temporary HDF5 file
    hid_t file_id = H5Fcreate("tempfile.h5", H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
    if (file_id < 0) {
        return 0;
    }

    // Create a dataset within the file to attach an attribute to
    hsize_t dims[1] = {1};
    hid_t dataspace_id = H5Screate_simple(1, dims, NULL);
    if (dataspace_id < 0) {
        H5Fclose(file_id);
        return 0;
    }

    hid_t dataset_id = H5Dcreate2(file_id, "dataset", H5T_NATIVE_INT, dataspace_id, H5P_DEFAULT, H5P_DEFAULT, H5P_DEFAULT);
    if (dataset_id < 0) {
        H5Sclose(dataspace_id);
        H5Fclose(file_id);
        return 0;
    }

    // Create an attribute to delete
    hid_t attr_id = H5Acreate2(dataset_id, "attribute", H5T_NATIVE_INT, dataspace_id, H5P_DEFAULT, H5P_DEFAULT);
    if (attr_id >= 0) {
        H5Aclose(attr_id);
    }

    // Prepare the attribute name from the input data
    char *attr_name = (char *)malloc(size + 1);
    if (attr_name == NULL) {
        H5Dclose(dataset_id);
        H5Sclose(dataspace_id);
        H5Fclose(file_id);
        return 0;
    }
    
    memcpy(attr_name, data, size);
    attr_name[size] = '\0';  // Null-terminate the string

    // Call the function-under-test
    H5Adelete(dataset_id, attr_name);

    // Clean up
    free(attr_name);
    H5Dclose(dataset_id);
    H5Sclose(dataspace_id);
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

    LLVMFuzzerTestOneInput_112(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
