#include <stdint.h>
#include <stddef.h>
#include <hdf5.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput_25(const uint8_t *data, size_t size) {
    // Initialize the HDF5 library
    H5open();

    // Ensure the input size is sufficient for a valid string
    if (size < 2) {
        return 0;
    }

    // Create a temporary file to work with
    hid_t file_id = H5Fcreate("tempfile.h5", H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
    if (file_id < 0) {
        return 0;
    }

    // Use part of the data as a group name, ensuring it is null-terminated
    size_t name_len = size < 255 ? size : 255;
    char group_name[256];
    memcpy(group_name, data, name_len);
    group_name[name_len] = '\0';

    // Use some arbitrary valid hid_t values for the other parameters
    hid_t lcpl_id = H5P_DEFAULT; // Link creation property list
    hid_t gcpl_id = H5P_DEFAULT; // Group creation property list
    hid_t gapl_id = H5P_DEFAULT; // Group access property list

    // Call the function-under-test
    hid_t group_id = H5Gcreate2(file_id, group_name, lcpl_id, gcpl_id, gapl_id);

    // Close the group if it was created successfully
    if (group_id >= 0) {
        H5Gclose(group_id);
    }

    // Close the file
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

    LLVMFuzzerTestOneInput_25(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
