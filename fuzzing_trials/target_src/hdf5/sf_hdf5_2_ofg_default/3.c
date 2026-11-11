#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <hdf5.h>

int LLVMFuzzerTestOneInput_3(const uint8_t *data, size_t size) {
    // Declare and initialize variables for the parameters of H5Dcreate2
    hid_t file_id = H5Fcreate("testfile.h5", H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
    hid_t space_id = H5Screate(H5S_SCALAR);
    hid_t type_id = H5Tcopy(H5T_NATIVE_INT);
    hid_t lcpl_id = H5P_DEFAULT; // Link creation property list
    hid_t dcpl_id = H5P_DEFAULT; // Dataset creation property list
    hid_t dapl_id = H5P_DEFAULT; // Dataset access property list

    // Ensure the data size is sufficient for a valid string
    if (size < 1) {
        H5Fclose(file_id);
        H5Sclose(space_id);
        H5Tclose(type_id);
        return 0;
    }

    // Allocate memory for the dataset name and ensure it's null-terminated
    char *dataset_name = (char *)malloc(size + 1);
    if (dataset_name == NULL) {
        H5Fclose(file_id);
        H5Sclose(space_id);
        H5Tclose(type_id);
        return 0;
    }
    memcpy(dataset_name, data, size);
    dataset_name[size] = '\0';

    // Call the function under test
    hid_t dataset_id = H5Dcreate2(file_id, dataset_name, type_id, space_id, lcpl_id, dcpl_id, dapl_id);

    // Clean up resources
    if (dataset_id >= 0) {
        H5Dclose(dataset_id);
    }
    H5Fclose(file_id);
    H5Sclose(space_id);
    H5Tclose(type_id);
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

    if(size < 1 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_3(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
