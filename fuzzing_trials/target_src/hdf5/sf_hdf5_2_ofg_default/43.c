#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <hdf5.h>

int LLVMFuzzerTestOneInput_43(const uint8_t *data, size_t size) {
    // Ensure the data is large enough to split into meaningful parts
    if (size < 7) { // Adjusted to ensure enough data for all parameters
        return 0;
    }

    // Initialize HDF5 library
    H5open();

    // Create a temporary file to use as the HDF5 file
    hid_t file_id = H5Fcreate("temp.h5", H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
    if (file_id < 0) {
        return 0;
    }

    // Use the first byte of data as a hid_t for the location
    hid_t loc_id = (hid_t)data[0];

    // Use the next byte as a length for the name
    size_t name_len = (size_t)data[1] % (size - 6); // Adjusted to ensure enough data remains
    char *name = (char *)malloc(name_len + 1);
    if (name == NULL) {
        H5Fclose(file_id);
        return 0;
    }
    memcpy(name, &data[2], name_len);
    name[name_len] = '\0';

    // Use the remaining bytes as hid_t values for type_id, space_id, lcpl_id, dcpl_id, dapl_id
    hid_t type_id = (hid_t)data[2 + name_len];
    hid_t space_id = (hid_t)data[3 + name_len];
    hid_t lcpl_id = (hid_t)data[4 + name_len];
    hid_t dcpl_id = (hid_t)data[5 + name_len];
    hid_t dapl_id = (hid_t)data[6 + name_len];

    // Call the function-under-test
    hid_t dataset_id = H5Dcreate2(loc_id, name, type_id, space_id, lcpl_id, dcpl_id, dapl_id);

    // Clean up
    if (dataset_id >= 0) {
        H5Dclose(dataset_id);
    }
    free(name);
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

    LLVMFuzzerTestOneInput_43(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
