#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <hdf5.h>

int LLVMFuzzerTestOneInput_113(const uint8_t *data, size_t size) {
    // Ensure that the size is sufficient to create a valid string
    if (size < 1) {
        return 0;
    }

    // Create a temporary HDF5 file
    hid_t file_id = H5Fcreate("tempfile.h5", H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
    if (file_id < 0) {
        return 0;
    }

    // Create a dataset within the file
    hsize_t dims[1] = {10};
    hid_t dataspace_id = H5Screate_simple(1, dims, NULL);
    hid_t dataset_id = H5Dcreate(file_id, "dataset", H5T_NATIVE_INT, dataspace_id, H5P_DEFAULT, H5P_DEFAULT, H5P_DEFAULT);
    H5Sclose(dataspace_id);

    // Create an attribute for the dataset
    hid_t attr_space_id = H5Screate(H5S_SCALAR);
    hid_t attr_id = H5Acreate(dataset_id, "attribute", H5T_NATIVE_INT, attr_space_id, H5P_DEFAULT, H5P_DEFAULT);
    H5Sclose(attr_space_id);
    H5Aclose(attr_id);

    // Prepare the attribute name from the input data
    size_t attr_name_size = size < 256 ? size : 255; // Limit the attribute name size
    char attr_name[256];
    memcpy(attr_name, data, attr_name_size);
    attr_name[attr_name_size] = '\0';

    // Call the function-under-test
    H5Adelete(dataset_id, attr_name);

    // Clean up and close the HDF5 objects
    H5Dclose(dataset_id);
    H5Fclose(file_id);

    // Remove the temporary file
    remove("tempfile.h5");

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

    LLVMFuzzerTestOneInput_113(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
